#!/usr/bin/env python3
"""
manifest_filter.py — strip server-stitched ads out of HLS and DASH manifests.

WHY THIS IS A SEPARATE PROCESS FROM YOUR DNS SERVER
───────────────────────────────────────────────────
DNS maps names to addresses. It never sees an HTTP response body, so it cannot
read or edit a .m3u8 / .mpd. And with true SSAI the ad segments are served from
the *same hostname* as the real video — that is the entire point of SSAI. Sink
that hostname at the DNS layer and the show dies with the ad.

So ad removal at the manifest level has to happen where the manifest is: in the
HTTP path. This module is a mitmproxy addon that rewrites manifest bodies in
flight, leaving the DNS server to do what DNS is good at (killing the ad
*decision* servers, trackers, and beacon endpoints that live on their own hosts).

USAGE
─────
    pip install mitmproxy
    mitmdump -s manifest_filter.py --listen-port 8080
    # then point the device at this box:8080 and install the mitmproxy CA cert

Standalone (no proxy — filter a file, useful for testing rules):
    python3 manifest_filter.py path/to/playlist.m3u8
    python3 manifest_filter.py --selftest
"""

from __future__ import annotations

import re
import sys
import logging
import xml.etree.ElementTree as ET

LOG = logging.getLogger("manifest_filter")

# ═══════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════

# Strip HLS Interstitials (Apple's EXT-X-DATERANGE ad mechanism, also what
# YouTube and Apple-stack players increasingly use). Almost always safe.
STRIP_INTERSTITIALS = True

# Strip SCTE-35 cue-out/cue-in bracketed ad pods and the segments inside them.
STRIP_CUE_BREAKS = True

# Strip segments whose URI path looks like an ad creative even with no cue tags.
STRIP_BY_URI_PATTERN = True

# Remove ad <Period>s from DASH and re-sequence the remaining ones so the
# timeline stays contiguous (a gap in the timeline stalls the player).
STRIP_DASH_AD_PERIODS = True

# A SCTE-35 EventStream marks where an ad *could* go. Broadcasters routinely
# leave those cues attached to content periods, so treating the cue alone as
# proof of an ad deletes real programming. Off by default; if you turn it on,
# DASH_MAX_AD_PERIOD_SECONDS keeps it from eating a feature-length period.
DASH_SCTE35_PERIOD_IS_AD = False
DASH_MAX_AD_PERIOD_SECONDS = 400.0

# Answer VAST/VMAP/ad-decision requests with a valid empty document instead of
# letting them fail. An empty response is a "no fill" — the player's ad module
# gets a clean answer, fires no impression beacon, and resumes content in one
# tick instead of waiting out its own timeout. That timeout is your hiccup.
NEUTRALIZE_VAST = True

# Content-Types we will consider rewriting.
HLS_CONTENT_TYPES = ("mpegurl", "x-mpegurl", "vnd.apple.mpegurl")
DASH_CONTENT_TYPES = ("dash+xml", "vnd.mpeg.dash.mpd")

# Segment URI substrings that mark an ad creative. Case-insensitive.
AD_URI_PATTERNS = [
    "/adbreak", "/ad-break", "/ad_break",
    "/adsegment", "/ad-segment",
    "/creative/", "/creatives/",
    "/preroll", "/midroll", "/postroll",
    "/adpod", "/ad-pod",
    "/adcontent", "/ad-content",
    "adaptive_ad", "_ad_break_",
    "/ads/", "/ad/",              # uplynk, mediatailor, generic stitchers
    "/dai/", "/ssai/",
    "/vast", "/vmap",
    "slate",                      # filler slate played around breaks
    "blackout",
]

# Compiled so a per-line check is cheap on 5000-line live playlists.
_AD_URI_RE = re.compile("|".join(re.escape(p) for p in AD_URI_PATTERNS), re.I)

# URL patterns that identify an ad-decision / VAST request worth neutralizing.
VAST_URL_RE = re.compile(
    r"(/vast|/vmap|ad_?tag|adtagurl|/ads\?|/ad_?request|/adrequest|"
    r"gampad/ads|pubads|/ondemand/(hls|dash)/ads)", re.I
)

# DASH Period @id / AssetIdentifier values that mark an ad period.
_DASH_AD_ID_RE = re.compile(r"(^|[-_/])ad(s|break|pod|period)?([-_/]|\d|$)", re.I)

SCTE35_SCHEMES = (
    "urn:scte:scte35",
    "urn:scte35",
    "urn:com:scte:scte35",
    "urn:dvb:iptv:cpm",           # some DVB ad signalling
)

EMPTY_VAST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<VAST version="4.0"></VAST>\n'
)
EMPTY_VMAP = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<vmap:VMAP xmlns:vmap="http://www.iab.net/videosuite/vmap" '
    'version="1.0"></vmap:VMAP>\n'
)


# ═══════════════════════════════════════════════════════════════════════════
# HLS
# ═══════════════════════════════════════════════════════════════════════════

def _is_interstitial_daterange(line: str) -> bool:
    """
    EXT-X-DATERANGE carrying an ad interstitial. These do not stitch segments
    inline — they tell the player to go load a *separate* asset mid-stream,
    which is the pause-and-play-something-else behaviour. Dropping the tag
    means the player never learns the interstitial exists.
    """
    up = line.upper()
    if "EXT-X-DATERANGE" not in up:
        return False
    return (
        "COM.APPLE.HLS.INTERSTITIAL" in up
        or "X-ASSET-URI" in up
        or "X-ASSET-LIST" in up
        or "SCTE35-OUT" in up
        or "SCTE35-IN" in up
        or "SCTE35-CMD" in up
        or 'CLASS="AD' in up
    )


def _daterange_duration(line: str) -> float | None:
    m = re.search(r"[,:](?:PLANNED-)?DURATION=([0-9.]+)", line, re.I)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _extinf_duration(line: str) -> float:
    m = re.match(r"#EXTINF:\s*([0-9.]+)", line, re.I)
    return float(m.group(1)) if m else 0.0


def filter_hls(text: str) -> tuple[str, int]:
    """
    Rewrite an HLS playlist with ad segments and ad markers removed.

    Returns (new_text, segments_removed).

    Handles, in order of how often they actually show up in the wild:
      • #EXT-X-CUE-OUT ... #EXT-X-CUE-IN pods  (segments between them dropped)
      • #EXT-X-DATERANGE SCTE35-OUT with DURATION (drop by accumulated time)
      • #EXT-X-DATERANGE interstitials (drop the tag; no segments involved)
      • Ad segments identified only by URI path
      • #EXT-OATCLS-SCTE35 / #EXT-X-SCTE35 / #EXT-X-ASSET side-channel tags
    Then repairs what removal breaks: TARGETDURATION, MEDIA-SEQUENCE, orphaned
    #EXT-X-DISCONTINUITY, and #EXT-X-KEY continuity.
    """
    lines = text.splitlines()
    out: list[str] = []

    in_break = False          # inside a cue-out/cue-in pod
    break_remaining = 0.0     # for duration-driven breaks with no explicit CUE-IN
    break_is_timed = False

    pending: list[str] = []   # tags buffered until we see the segment URI
    pending_disc = False      # a DISCONTINUITY we have not committed yet
    dropped_since_emit = False

    current_key: str | None = None      # last #EXT-X-KEY seen
    emitted_key: str | None = None      # last #EXT-X-KEY we actually wrote

    removed = 0
    max_dur = 0.0
    leading_drops = 0         # segments dropped before the first kept segment
    seen_kept_segment = False

    for raw in lines:
        line = raw.rstrip("\r")
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("#"):
            up = stripped.upper()

            # ── cue-out: start of an ad pod ──────────────────────────────
            if STRIP_CUE_BREAKS and (
                up.startswith("#EXT-X-CUE-OUT")
                or up.startswith("#EXT-OATCLS-SCTE35")
                or up.startswith("#EXT-X-SCTE35")
                or up.startswith("#EXT-X-CUE-OUT-CONT")
            ):
                if not up.startswith("#EXT-X-CUE-OUT-CONT"):
                    in_break = True
                    break_is_timed = False
                continue

            # ── cue-in: end of an ad pod ────────────────────────────────
            if STRIP_CUE_BREAKS and up.startswith("#EXT-X-CUE-IN"):
                in_break = False
                break_is_timed = False
                pending_disc = False      # the return-to-content discontinuity
                continue

            # ── DATERANGE: interstitial or SCTE-35 signalling ───────────
            if _is_interstitial_daterange(stripped):
                if not STRIP_INTERSTITIALS and "SCTE35" not in up:
                    out.append(line)
                    continue
                if STRIP_CUE_BREAKS and "SCTE35-OUT" in up:
                    dur = _daterange_duration(stripped)
                    if dur:
                        in_break = True
                        break_is_timed = True
                        break_remaining = dur
                if "SCTE35-IN" in up:
                    in_break = False
                    break_is_timed = False
                continue

            # ── other ad side-channel tags ──────────────────────────────
            if up.startswith("#EXT-X-ASSET") or up.startswith("#EXT-X-AD"):
                continue

            # ── key rotation: ads usually carry their own key ───────────
            if up.startswith("#EXT-X-KEY"):
                current_key = line
                continue

            # ── discontinuity: buffer, decide when we commit a segment ──
            if up.startswith("#EXT-X-DISCONTINUITY") and not up.startswith(
                "#EXT-X-DISCONTINUITY-SEQUENCE"
            ):
                pending_disc = True
                continue

            # ── per-segment tags: buffer until we see the URI ───────────
            if up.startswith("#EXTINF") or up.startswith("#EXT-X-BYTERANGE") \
               or up.startswith("#EXT-X-MAP") or up.startswith("#EXT-X-PROGRAM-DATE-TIME"):
                pending.append(line)
                continue

            # ── TARGETDURATION recomputed at the end ────────────────────
            if up.startswith("#EXT-X-TARGETDURATION"):
                out.append("#EXT-X-TARGETDURATION:__RECALC__")
                continue

            out.append(line)
            continue

        # ─────────────── this is a segment URI ───────────────
        seg_dur = 0.0
        for p in pending:
            if p.upper().startswith("#EXTINF"):
                seg_dur = _extinf_duration(p)

        is_ad = in_break or (STRIP_BY_URI_PATTERN and bool(_AD_URI_RE.search(stripped)))

        if in_break and break_is_timed:
            break_remaining -= seg_dur
            if break_remaining <= 0.01:
                in_break = False
                break_is_timed = False

        if is_ad:
            removed += 1
            dropped_since_emit = True
            if not seen_kept_segment:
                leading_drops += 1
            pending = []
            continue

        # keeping this segment — commit its context first
        if current_key is not None and current_key != emitted_key:
            out.append(current_key)
            emitted_key = current_key

        if pending_disc:
            # Only a real discontinuity if we did NOT just remove the thing it
            # was separating. If we dropped the ad pod, content is contiguous
            # again and the marker would make the player flush its decoder for
            # no reason — that flush is itself a visible hitch.
            if not dropped_since_emit:
                out.append("#EXT-X-DISCONTINUITY")
            pending_disc = False

        out.extend(pending)
        out.append(line)
        pending = []
        dropped_since_emit = False
        seen_kept_segment = True
        max_dur = max(max_dur, seg_dur)

    # ── repair TARGETDURATION and MEDIA-SEQUENCE ─────────────────────────
    target = str(int(max_dur + 0.999)) if max_dur else "10"
    fixed: list[str] = []
    for line in out:
        if line == "#EXT-X-TARGETDURATION:__RECALC__":
            fixed.append(f"#EXT-X-TARGETDURATION:{target}")
        elif leading_drops and line.upper().startswith("#EXT-X-MEDIA-SEQUENCE"):
            # We removed segments from the front of a live window. The sequence
            # number must advance by that many or the player will think the
            # playlist rolled backwards and reset its buffer.
            try:
                base = int(line.split(":", 1)[1].strip())
                fixed.append(f"#EXT-X-MEDIA-SEQUENCE:{base + leading_drops}")
            except (ValueError, IndexError):
                fixed.append(line)
        else:
            fixed.append(line)

    return "\n".join(fixed) + "\n", removed


# ═══════════════════════════════════════════════════════════════════════════
# DASH
# ═══════════════════════════════════════════════════════════════════════════

def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _parse_iso_duration(s: str | None) -> float:
    """Minimal ISO-8601 duration parser for the PT#H#M#S form MPDs use."""
    if not s:
        return 0.0
    m = re.match(
        r"^P(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)D)?"
        r"(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?$",
        s.strip(),
    )
    if not m:
        return 0.0
    y, mo, d, h, mi, sec = (float(x) if x else 0.0 for x in m.groups())
    return y * 31536000 + mo * 2592000 + d * 86400 + h * 3600 + mi * 60 + sec


def _fmt_iso_duration(seconds: float) -> str:
    if seconds <= 0:
        return "PT0S"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    out = "PT"
    if h >= 1:
        out += f"{int(h)}H"
    if m >= 1:
        out += f"{int(m)}M"
    if s or out == "PT":
        out += f"{s:.3f}".rstrip("0").rstrip(".") + "S"
    return out


def _period_is_ad(period: ET.Element) -> bool:
    """
    Classify a <Period> as ad or content.

    Deliberately asymmetric: a false positive deletes programming the user
    asked for, a false negative shows one ad. So this requires a *strong*
    signal — something that names the period as an ad — and treats a bare
    SCTE-35 cue as insufficient, because content periods carry those too.
    """
    pid = period.get("id") or ""
    if _DASH_AD_ID_RE.search(pid):
        return True

    has_scte35 = False

    for child in period.iter():
        ln = _localname(child.tag)
        scheme = (child.get("schemeIdUri") or "").lower()

        if ln in ("EventStream", "InbandEventStream") and any(
            s in scheme for s in SCTE35_SCHEMES
        ):
            has_scte35 = True

        # AssetIdentifier is the standards-blessed way a stitcher labels an
        # ad period — DASH-IF ad-insertion scheme, or an ad-ish content id.
        if ln == "AssetIdentifier":
            if "ad" in scheme or _DASH_AD_ID_RE.search(child.get("value") or ""):
                return True

        if ln == "SupplementalProperty" and "adinsertion" in scheme.replace("-", ""):
            return True

    if has_scte35 and DASH_SCTE35_PERIOD_IS_AD:
        dur = _parse_iso_duration(period.get("duration"))
        # A cue on a period the length of an actual ad pod is good evidence.
        # A cue on a 45-minute period is a broadcaster marking a future break.
        if 0 < dur <= DASH_MAX_AD_PERIOD_SECONDS:
            return True

    return False


def filter_dash(text: str) -> tuple[str, int]:
    """
    Rewrite an MPD with ad Periods removed and the timeline re-sequenced.

    Returns (new_text, periods_removed). If anything fails to parse, returns
    the original text unchanged — a broken MPD is worse than an ad.
    """
    try:
        # Preserve the default namespace so the output is still a valid MPD.
        ns_match = re.search(r'xmlns\s*=\s*"([^"]+)"', text)
        if ns_match:
            ET.register_namespace("", ns_match.group(1))
        for pfx, uri in re.findall(r'xmlns:([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"', text):
            ET.register_namespace(pfx, uri)

        root = ET.fromstring(text)
    except ET.ParseError as exc:
        LOG.warning("MPD parse failed, passing through: %s", exc)
        return text, 0

    if _localname(root.tag) != "MPD":
        return text, 0

    periods = [c for c in list(root) if _localname(c.tag) == "Period"]
    removed = 0

    if STRIP_DASH_AD_PERIODS:
        for p in periods:
            if _period_is_ad(p):
                root.remove(p)
                removed += 1

    # Strip SCTE-35 signalling from the periods we kept. These are the cue
    # points that draw ad markers on the scrub bar and that trigger the
    # player's "an ad is due here" logic even when no ad period remains.
    for p in [c for c in list(root) if _localname(c.tag) == "Period"]:
        for parent in [p] + list(p.iter()):
            for child in list(parent):
                if _localname(child.tag) in ("EventStream", "InbandEventStream"):
                    scheme = (child.get("schemeIdUri") or "").lower()
                    if any(s in scheme for s in SCTE35_SCHEMES):
                        parent.remove(child)

    # Re-sequence @start so the remaining periods are contiguous. A hole in the
    # timeline is exactly the stall the removal was meant to prevent.
    if removed:
        cursor = 0.0
        for p in [c for c in list(root) if _localname(c.tag) == "Period"]:
            if p.get("start") is not None:
                p.set("start", _fmt_iso_duration(cursor))
            cursor += _parse_iso_duration(p.get("duration"))

        # mediaPresentationDuration must shrink by what we removed, or the
        # player waits at the end for content that will never arrive.
        total = sum(
            _parse_iso_duration(p.get("duration"))
            for p in root
            if _localname(p.tag) == "Period"
        )
        if root.get("mediaPresentationDuration") and total > 0:
            root.set("mediaPresentationDuration", _fmt_iso_duration(total))

    body = ET.tostring(root, encoding="unicode", xml_declaration=True)
    return body, removed


# ═══════════════════════════════════════════════════════════════════════════
# mitmproxy addon
# ═══════════════════════════════════════════════════════════════════════════

class ManifestFilter:
    """mitmproxy addon. Registered at the bottom of this file."""

    def __init__(self) -> None:
        self.hls_segments_removed = 0
        self.dash_periods_removed = 0
        self.vast_neutralized = 0

    # --- request side: kill ad-decision calls before they leave -----------
    def request(self, flow) -> None:
        if not NEUTRALIZE_VAST:
            return
        url = flow.request.pretty_url
        if VAST_URL_RE.search(url):
            from mitmproxy import http
            is_vmap = "vmap" in url.lower()
            body = EMPTY_VMAP if is_vmap else EMPTY_VAST
            flow.response = http.Response.make(
                200,
                body.encode(),
                {"Content-Type": "application/xml", "Cache-Control": "max-age=300"},
            )
            self.vast_neutralized += 1
            LOG.info("VAST no-fill: %s", url[:120])

    # --- response side: rewrite manifests ---------------------------------
    def response(self, flow) -> None:
        resp = flow.response
        if resp is None or not resp.content:
            return

        ctype = (resp.headers.get("content-type") or "").lower()
        path = flow.request.path.lower().split("?")[0]

        is_hls = any(t in ctype for t in HLS_CONTENT_TYPES) or path.endswith(
            (".m3u8", ".m3u")
        )
        is_dash = any(t in ctype for t in DASH_CONTENT_TYPES) or path.endswith(".mpd")

        if not (is_hls or is_dash):
            return

        try:
            text = resp.get_text(strict=False)
        except Exception:
            return
        if not text:
            return

        if is_hls:
            new, n = filter_hls(text)
            if n or new != text:
                resp.set_text(new)
                self.hls_segments_removed += n
                if n:
                    LOG.info("HLS: removed %d ad segments from %s", n, path[:100])
        else:
            new, n = filter_dash(text)
            if n or new != text:
                resp.set_text(new)
                self.dash_periods_removed += n
                if n:
                    LOG.info("DASH: removed %d ad periods from %s", n, path[:100])

        # A rewritten body must not carry the original length or a stale
        # validator, or the client may refuse it.
        resp.headers.pop("content-length", None)
        resp.headers.pop("etag", None)
        resp.headers["cache-control"] = "no-store"


addons = [ManifestFilter()]


# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE / SELFTEST
# ═══════════════════════════════════════════════════════════════════════════

_TEST_HLS_CUE = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:100
#EXTINF:9.009,
content0.ts
#EXTINF:9.009,
content1.ts
#EXT-X-CUE-OUT:30.0
#EXT-X-DISCONTINUITY
#EXTINF:10.0,
https://ads.example.com/creative/ad0.ts
#EXTINF:10.0,
https://ads.example.com/creative/ad1.ts
#EXTINF:10.0,
https://ads.example.com/creative/ad2.ts
#EXT-X-CUE-IN
#EXT-X-DISCONTINUITY
#EXTINF:9.009,
content2.ts
#EXTINF:9.009,
content3.ts
#EXT-X-ENDLIST
"""

_TEST_HLS_INTERSTITIAL = """#EXTM3U
#EXT-X-TARGETDURATION:6
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-DATERANGE:ID="ad1",CLASS="com.apple.hls.interstitial",START-DATE="2026-01-01T00:00:10Z",DURATION=15.0,X-ASSET-URI="https://ads.example.com/pod.m3u8",X-RESUME-OFFSET=0
#EXTINF:6.0,
seg0.ts
#EXTINF:6.0,
seg1.ts
#EXT-X-ENDLIST
"""

_TEST_HLS_LEADING = """#EXTM3U
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:500
#EXTINF:10.0,
/ads/preroll0.ts
#EXTINF:10.0,
/ads/preroll1.ts
#EXTINF:4.0,
real0.ts
"""

_TEST_DASH = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="static"
     mediaPresentationDuration="PT10M0S">
  <Period id="content-1" start="PT0S" duration="PT4M0S">
    <AdaptationSet mimeType="video/mp4"><Representation id="v1"/></AdaptationSet>
  </Period>
  <Period id="ad-break-1" start="PT4M0S" duration="PT0M30S">
    <EventStream schemeIdUri="urn:scte:scte35:2013:xml"/>
    <AdaptationSet mimeType="video/mp4"><Representation id="adv1"/></AdaptationSet>
  </Period>
  <Period id="content-2" start="PT4M30S" duration="PT5M30S">
    <EventStream schemeIdUri="urn:scte:scte35:2013:xml"/>
    <AdaptationSet mimeType="video/mp4"><Representation id="v2"/></AdaptationSet>
  </Period>
</MPD>
"""


def _selftest() -> int:
    failures = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        if cond:
            print(f"  PASS  {name}")
        else:
            failures += 1
            print(f"  FAIL  {name}  {detail}")

    print("HLS — SCTE-35 cue-out/cue-in pod")
    out, n = filter_hls(_TEST_HLS_CUE)
    check("3 ad segments removed", n == 3, f"got {n}")
    check("no ad URIs remain", "ads.example.com" not in out)
    check("all 4 content segments kept", out.count("content") == 4)
    check("cue tags gone", "CUE-OUT" not in out and "CUE-IN" not in out)
    check("orphaned discontinuity swallowed", "DISCONTINUITY" not in out)
    check("targetduration recomputed", "#EXT-X-TARGETDURATION:10" in out)
    check("media-sequence untouched (no leading drops)",
          "#EXT-X-MEDIA-SEQUENCE:100" in out)

    print("\nHLS — Apple interstitial DATERANGE")
    out, n = filter_hls(_TEST_HLS_INTERSTITIAL)
    check("interstitial tag stripped", "DATERANGE" not in out)
    check("no asset URI leaks", "X-ASSET-URI" not in out)
    check("content segments intact", out.count("seg") == 2)

    print("\nHLS — leading pre-roll in a live window")
    out, n = filter_hls(_TEST_HLS_LEADING)
    check("2 preroll segments removed", n == 2, f"got {n}")
    check("media-sequence advanced 500→502",
          "#EXT-X-MEDIA-SEQUENCE:502" in out, out)

    print("\nDASH — multi-period ad insertion")
    out, n = filter_dash(_TEST_DASH)
    check("1 ad period removed", n == 1, f"got {n}")
    check("ad period id gone", "ad-break-1" not in out)
    check("both content periods kept",
          "content-1" in out and "content-2" in out)
    check("scte-35 eventstream stripped from kept period",
          "scte35" not in out.lower())
    check("timeline re-sequenced (content-2 now starts at 4m)",
          'start="PT4M"' in out or 'start="PT4M0S"' in out, out)
    check("presentation duration shrunk",
          "PT9M30S" in out or "PT9M30" in out, out)
    check("still parses as XML", _reparses(out))

    print("\nDASH — false-positive guards")
    cued_content = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" mediaPresentationDuration="PT45M0S">
  <Period id="feature" start="PT0S" duration="PT45M0S">
    <EventStream schemeIdUri="urn:scte:scte35:2013:xml"/>
    <AdaptationSet mimeType="video/mp4"><Representation id="v1"/></AdaptationSet>
  </Period>
</MPD>
"""
    out, n = filter_dash(cued_content)
    check("cue-bearing content period NOT deleted", n == 0 and "feature" in out)
    check("but its cue markers ARE stripped", "scte35" not in out.lower())

    innocuous = """<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011">
  <Period id="adaptation-set-group-1" duration="PT1M0S"/>
  <Period id="broadcast-2" duration="PT1M0S"/>
</MPD>
"""
    out, n = filter_dash(innocuous)
    check("'adaptation'/'broadcast' ids not mistaken for ads", n == 0, f"got {n}")

    print("\nRobustness")
    check("malformed MPD passes through", filter_dash("<not xml")[0] == "<not xml")
    check("empty playlist survives", filter_hls("")[0].strip() == "")
    plain = "#EXTM3U\n#EXT-X-TARGETDURATION:4\n#EXTINF:4.0,\na.ts\n"
    out, n = filter_hls(plain)
    check("ad-free playlist keeps its segment", "a.ts" in out and n == 0)

    print(f"\n{'ALL PASS' if not failures else str(failures) + ' FAILURE(S)'}")
    return 1 if failures else 0


def _reparses(xml_text: str) -> bool:
    try:
        ET.fromstring(xml_text)
        return True
    except ET.ParseError:
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if args[0] == "--selftest":
        sys.exit(_selftest())

    path = args[0]
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = fh.read()
    if path.lower().endswith(".mpd") or data.lstrip().startswith("<"):
        new, n = filter_dash(data)
        sys.stderr.write(f"removed {n} ad period(s)\n")
    else:
        new, n = filter_hls(data)
        sys.stderr.write(f"removed {n} ad segment(s)\n")
    sys.stdout.write(new)
