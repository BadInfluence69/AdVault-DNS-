# python DNS_Ad_Blocker.py
# ipconfig /flushdns
# mitmdump -s manifest_filter.py --listen-port 8080

import os
import io
import re
import sys
import ssl
import json
import math
import time
import socket
import struct
import signal
import tempfile
import threading
import datetime
import ipaddress
from collections import defaultdict, deque, Counter
from concurrent.futures import ThreadPoolExecutor

import requests
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE, SOA
from colorama import Fore, Back, Style, init

# ── stdout/stderr resilience ──────────────────────────────────────────────────
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
init(autoreset=True)

# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL THEME  — centralised color definitions
# ══════════════════════════════════════════════════════════════════════════════
C = {
    # General
    "RESET"     : Style.RESET_ALL,
    "BANNER"    : Fore.CYAN  + Style.BRIGHT,
    "HEADER"    : Fore.WHITE + Style.BRIGHT,
    "TIMESTAMP" : Fore.WHITE + Style.DIM,
    "INFO"      : Fore.CYAN,
    "OK"        : Fore.GREEN + Style.BRIGHT,
    "WARN"      : Fore.YELLOW,
    "ERROR"     : Fore.RED   + Style.BRIGHT,
    "FATAL"     : Back.RED   + Fore.WHITE + Style.BRIGHT,
    # DNS events
    "BLOCKED"   : Fore.RED,
    "ALLOWED"   : Fore.GREEN,
    "IP_DENIED" : Back.RED + Fore.WHITE + Style.BRIGHT,
    "RESOLVED"  : Fore.BLUE,
    "CACHE_HIT" : Fore.CYAN,
    "QUERY"     : Fore.WHITE + Style.DIM,
    # Threat signals
    "INJECTION" : Fore.MAGENTA + Style.BRIGHT,
    "AD_SIGNAL" : Fore.MAGENTA,
    "AUTO_BLOCK": Fore.RED    + Style.BRIGHT,
    "DISCOVERY" : Fore.YELLOW + Style.BRIGHT,
    # GEO
    "GEO"       : Fore.CYAN   + Style.BRIGHT,
    # Stats
    "STAT_KEY"  : Fore.WHITE  + Style.BRIGHT,
    "STAT_VAL"  : Fore.YELLOW + Style.BRIGHT,
    "STAT_GOOD" : Fore.GREEN  + Style.BRIGHT,
    "STAT_BAD"  : Fore.RED    + Style.BRIGHT,
    # SSAI / Manifest manipulation (new)
    "SSAI"      : Fore.RED    + Style.BRIGHT,
    "MANIFEST"  : Fore.YELLOW + Style.BRIGHT,
}

def _c(key: str) -> str:
    return C.get(key, "")

# ══════════════════════════════════════════════════════════════════════════════
# STARTUP BANNER
# ══════════════════════════════════════════════════════════════════════════════
BANNER = f"""
{_c('BANNER')}╔══════════════════════════════════════════════════════════════╗
║          AdVault DNS  —  Ad-Blocking Resolver v3.0           ║
║   DoT + DoH + Auto-Evolve + Injection Guard + SSAI Shield    ║
║   github.com/BadInfluence69/AdVault-DNS-  |  Brian Cambron   ║
╚══════════════════════════════════════════════════════════════╝{_c('RESET')}"""

# ══════════════════════════════════════════════════════════════════════════════
# INTERCEPTION STUBS  (DNS-only; SNI proxy not implemented here)
# ══════════════════════════════════════════════════════════════════════════════
YOUTUBE_INTERCEPT_IP  = "185.107.97.246"
INTERCEPT_YOUTUBE_ADS = True
SNI_PROXY_PORT        = 443

YT_AD_REGEX = re.compile(
    r"(^|\.)r[0-9]+---sn-[a-z0-9]+\.googlevideo\.com$", re.IGNORECASE
)

# ══════════════════════════════════════════════════════════════════════════════
# CORE SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
LISTEN_HOST       = "0.0.0.0"
DNS_UDP_PORT      = 53
DNS_TCP_PORT      = 53
DOT_PORT          = 853

UDP_WORKERS       = 500
TCP_BACKLOG       = 256
TCP_CLIENT_TIMEOUT = 5.0

DOT_CERTFILE = "fullchain.pem"
DOT_KEYFILE  = "privkey.pem"
DOT_HOSTNAME = os.environ.get("ADV_DNS_HOSTNAME", "localhost")

# ══════════════════════════════════════════════════════════════════════════════
# AUTO-GENERATE TLS KEYS / CERTIFICATE  (if missing)
# ══════════════════════════════════════════════════════════════════════════════
def _resolve_dot_paths():
    """Return absolute paths for cert/key relative to this script's directory."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert = os.path.join(script_dir, DOT_CERTFILE)
    key  = os.path.join(script_dir, DOT_KEYFILE)
    return cert, key

def auto_generate_dot_certificates():
    """
    Auto-generate a self-signed RSA-2048 TLS certificate + private key
    in the same folder as this script if either file is missing.

    Uses only the Python standard library (ssl + subprocess via openssl)
    with a pure-Python fallback using the `cryptography` package when
    available.  The files written match DOT_CERTFILE / DOT_KEYFILE exactly.
    """
    cert_path, key_path = _resolve_dot_paths()

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return  # nothing to do

    print(f"\n[AdVault DNS] TLS key/cert not found — auto-generating …")
    print(f"  cert → {cert_path}")
    print(f"  key  → {key_path}\n")

    # ── Strategy 1: use the `cryptography` package (preferred) ───────────────
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as _dt

        # Generate RSA-2048 private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Build self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "Local"),
            x509.NameAttribute(NameOID.LOCALITY_NAME,            "AdVault"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "AdVault DNS"),
            x509.NameAttribute(NameOID.COMMON_NAME,              DOT_HOSTNAME),
        ])

        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _dt.timedelta(days=3650))   # 10-year cert
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(DOT_HOSTNAME),
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Write private key (PEM, no passphrase)
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Write certificate chain (single self-signed cert)
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("[AdVault DNS] ✔  TLS certificate generated via `cryptography` package.")
        print(f"              CN={DOT_HOSTNAME}  valid 10 years\n")
        return

    except ImportError:
        pass  # fall through to openssl subprocess strategy
    except Exception as e:
        print(f"[AdVault DNS] WARN: cryptography-based cert gen failed: {e}")

    # ── Strategy 2: shell out to openssl (available on most systems) ──────────
    try:
        import subprocess, shutil

        openssl_bin = shutil.which("openssl")
        if not openssl_bin:
            raise FileNotFoundError("openssl binary not found in PATH")

        subj = (
            f"/C=US/ST=Local/L=AdVault/O=AdVaultDNS"
            f"/CN={DOT_HOSTNAME}"
        )
        san_ext = (
            f"subjectAltName=DNS:{DOT_HOSTNAME},"
            f"IP:185.107.97.246"
        )

        cmd = [
            openssl_bin, "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out",    cert_path,
            "-days",   "3650",
            "-nodes",
            "-subj",   subj,
            "-addext", san_ext,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode == 0 and os.path.exists(cert_path) and os.path.exists(key_path):
            print("[AdVault DNS] ✔  TLS certificate generated via openssl CLI.")
            print(f"              CN={DOT_HOSTNAME}  valid 10 years\n")
            return
        else:
            print(f"[AdVault DNS] WARN: openssl returned {result.returncode}: {result.stderr.strip()}")

    except Exception as e:
        print(f"[AdVault DNS] WARN: openssl-based cert gen failed: {e}")

    # ── Strategy 3: pure Python using only stdlib ssl + tempfile ─────────────
    print(
        "[AdVault DNS] ERROR: Could not auto-generate TLS certificates.\n"
        "  Please install the `cryptography` package:  pip install cryptography\n"
        "  OR place your own fullchain.pem / privkey.pem next to this script.\n"
        "  DNS-over-TLS (port 853) will be DISABLED until certificates exist.\n"
    )

# Plain UDP/TCP upstreams (fallback)
UPSTREAMS = [("185.222.222.222", 53)]
UPSTREAM_TCP_TIMEOUT = 5.0
UPSTREAM_UDP_TIMEOUT = 5.0

# ── DNS-over-HTTPS upstream ───────────────────────────────────────────────────
DOH_ENABLED  = True
DOH_TIMEOUT  = 5.0
DOH_UPSTREAMS = [
    "https://8.8.8.8/dns-query",
]
_doh_idx      = 0
_doh_idx_lock = threading.Lock()

# ── Sinkhole IPs ──────────────────────────────────────────────────────────────
# CRITICAL: these MUST be non-routable. A blocked domain that resolves to a
# reachable-looking public address makes the client open a TCP connection that
# never completes — it hangs for the full OS connect timeout (20s+ on most
# stacks). For a video player, that stall is indistinguishable from a hung ad
# server and freezes the playback pipeline. Fail FAST, never slow.
SINK_IPv4 = "0.0.0.0"   # unspecified — immediate local failure, no packet sent
SINK_IPv6 = "::"        # unspecified — same, for AAAA

# ── Block response strategy ───────────────────────────────────────────────────
# How to answer a query for a blocked domain. Different players react to
# different failure signals; this is tunable per-deployment.
#
#   "nxdomain" — RCODE=3 + SOA. Fastest, cleanest failure. Stub resolvers
#                negative-cache it (RFC 2308) so repeat lookups during a
#                stream cost nothing. Best default for video.
#   "null"     — NOERROR + 0.0.0.0 / ::. Connection fails instantly at the
#                socket layer. Use if a player misbehaves on NXDOMAIN.
#   "refused"  — RCODE=5. Fast, but some stubs then retry a secondary DNS
#                server and route around the block entirely. Avoid.
BLOCK_MODE = "nxdomain"

# Negative-cache TTL advertised in the SOA MINIMUM field, in seconds.
# Kept short so unblocking a domain takes effect quickly, but long enough
# that a player fetching segments every few seconds doesn't re-query on
# every single segment boundary.
BLOCK_NEGATIVE_TTL = 60

# Two-part public suffixes, for picking a sane SOA owner name.
_TWO_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "or.jp", "ne.jp",
    "com.au", "net.au", "org.au", "co.nz", "com.br", "com.mx", "co.in",
    "com.cn", "com.tr", "co.za", "com.sg", "co.kr", "com.tw",
}


CACHE_MAX_ENTRIES = 60
CACHE_TTL_CAP     = 15

# ── File paths ────────────────────────────────────────────────────────────────
blocklist_file  = "dynamic_blocklist.txt"
allowlist_file  = "allowlist.txt"
discovered_file = "discovered_blocklist.txt"
ad_insights_log = "ad_insights.txt"
catalog_file    = "candidates_catalog.json"

# ── Client IP allowlist (access control) ───────────────────────────────────────
# Only clients whose source IP appears in this file are permitted to use the
# DNS service. Everyone else is rejected before their query is ever resolved.
IP_ALLOWLIST_ENABLED = True
IP_ALLOWLIST_FILE    = "allowed_ips.txt"

# ── Dashboard / users file ────────────────────────────────────────────────────
USERS_FILE           = "current_users.txt"
USERS_WRITE_INTERVAL = 5      # seconds between file rewrites
USERS_ACTIVE_WINDOW  = 5      # rolling window for active-client counts

# ── Live terminal stats ticker ────────────────────────────────────────────────
TERMINAL_STATS_INTERVAL = 15   # print a colored stats line to console every N seconds
TERMINAL_STATS_ENABLED  = True

# ── Abuse / anomaly thresholds (flags only — no auto-block by default) ────────
HOT_QPS_THRESHOLD         = 200.0
RANDOMISH_RATIO_THRESHOLD = 0.50
SAMPLE_EVERY_N_QUERIES    = 25
SAMPLE_MAX_ITEMS_PER_IP   = 200

SHORT_MARKER_MAXLEN = 5

# ══════════════════════════════════════════════════════════════════════════════
# AUTO-EVOLVE SETTINGS
# ══════════════════════════════════════════════════════════════════════════════
AUTO_ADD_DISCOVERED_TO_BLOCKLIST  = True
AUTO_BLOCK_DISCOVERED_IMMEDIATELY = True   # sink the *first* triggering query too

# ── Weighted candidate scoring ────────────────────────────────────────────────
# A domain is flagged as an ad candidate when its score >= threshold.
AD_CANDIDATE_SCORE_THRESHOLD = 2.0

AD_SIGNAL_WEIGHTS = {
    "keyword_match"  : 2.0,   # substring keyword from AD_HOST_KEYWORDS
    "regex_match"    : 2.5,   # compiled regex from AD_HOST_REGEXES
    "marker_keyword" : 1.5,   # AD_MARKER_KEYWORDS hit
    "randomish"      : 1.0,   # high-entropy random-looking subdomain
    "tld_suspicious" : 0.5,   # e.g. .xyz, .click, .bid, .loan
    "ssai_signal"    : 3.0,   # SSAI / manifest-manipulation hostname match (new)
}
AD_SUSPICIOUS_TLDS = {".xyz", ".click", ".bid", ".loan", ".win", ".top", ".men", ".dev", ".date"}

# ══════════════════════════════════════════════════════════════════════════════
# GEO SPOOFING / OVERRIDES  (opt-in)
# ══════════════════════════════════════════════════════════════════════════════
GEO_ENABLED        = True
GEO_LOOKUP_TIMEOUT = 15
GEO_CACHE_TTL      = 24 * 15
GEO_LOOKUP_URL     = "https://107.149.207.104/{ip}"
# e.g. "https://example-geoip/api/{ip}"

GEO_SPOOF_RULES_A    = {}
GEO_SPOOF_RULES_AAAA = {}
GEO_OVERRIDE_PRECEDENCE_BEFORE_BLOCKING = True

# ══════════════════════════════════════════════════════════════════════════════
# BLOCKLIST SOURCES
# ══════════════════════════════════════════════════════════════════════════════
blocklist_urls = [
    "http://72.51.249.70/123/dynamic_blocklist.txt",
]

allowlist_critical = {
    "youtube.com", "www.youtube.com", "m.youtube.com",
    "ytimg.com", "i.ytimg.com", "s.ytimg.com", "yt3.ggpht.com",
    "googlevideo.com", "*.googlevideo.com", "ggpht.com", "*.ggpht.com",
    "googleusercontent.com", "lh3.googleusercontent.com",
    "googleapis.com", "youtubei.googleapis.com", "update.googleapis.com",
    "gstatic.com", "www.gstatic.com", "check.gstatic.com", "connectivity-check.gstatic.com",
    "accounts.google.com", "apis.google.com", "s.youtube.com", "video.google.com",
    "youtube-ui.l.google.com", "tv.youtube.com", "chart.js"
}

# ── Ad host keyword list ──────────────────────────────────────────────────────
AD_HOST_KEYWORDS_RAW = [
    #// feed / homepage
        'ytd-ad-slot-renderer',
        'ytd-in-feed-ad-layout-renderer',
        'ytd-banner-promo-renderer',
        'ytd-banner-promo-renderer-background',
        'ytd-statement-banner-renderer',
        'ytd-primetime-promo-renderer',
        'ytd-brand-video-shelf-renderer',
        'ytd-brand-video-singleton-renderer',
        'ytd-inline-survey-renderer',
        '#masthead-ad',
        #// search
        'ytd-promoted-sparkles-web-renderer',
        'ytd-promoted-sparkles-text-search-renderer',
        'ytd-promoted-video-renderer',
        'ytd-search-pyv-renderer',
        'ytd-carousel-ad-renderer',
       # // watch page
        'ytd-display-ad-renderer',
        'ytd-compact-promoted-video-renderer',
        'ytd-compact-promoted-item-renderer',
        'ytd-action-companion-ad-renderer',
        'ytd-companion-slot-renderer',
        'ytd-player-legacy-desktop-watch-ads-renderer',
        '#player-ads',
        '#offer-module',
        # // mobile
        'ytm-promoted-video-renderer',
        'ytm-promoted-sparkles-web-renderer',
        'ytm-companion-slot',
        'ytm-carousel-ad-renderer',
    r"HLS", r"DASH",
    r"page_ads",
    r"timestamp",
    r"origin-trial",
    r"EXT-X-CUE-OUT",
    r"SCTE-35",
    r"SCT-35",
    r"SCT-35.manifest",
    r"manifest",
    r"manifestmpd",
    r"manifest.kson",
    r"ApvK67ociHgr2egd6c2ZjrfPuRs8BHcvSggogIOPQNH7GJ3cVlyJ1NOq/COCdj0+zxskqHt9HgLLETc8qqD+vwsAAABteyJvcmlnaW4iOiJodHRwczovL3lvdXR1YmUuY29tOjQ0MyIsImZlYXR1cmUiOiJQcml2YWN5U2FuZGJveEFkc0FQSXMiLCJleHBpcnkiOjE2OTUxNjc5OTksImlzU3ViZG9tYWluIjp0cnVlfQ==",
    r"r3---sn-4g57kn6z.googlevideo.com",
    r"r1---sn-4g57kn7z.googlevideo.com",
    r"r5---sn-8xg7en7z.googlevideo.com",
    r"[0-9]+[a-z0-9]+\.hbomax\.com",
    r"[0-9]+---sn-[a-z0-9]+\.googlevideo\.com",
    "ad.", ".ad.", "ads.", ".ads.", "adservice", "adserver", "advert",
    "doubleclick", "googlesyndication", "googletagservices", "googletagmanager",
    "adnxs", "moatads", "taboola", "outbrain", "criteo", "rubiconproject",
    "serving-sys", "zemanta", "pubmatic", "yieldmo", "omtrdc",
    "scorecardresearch", "zedo", "revcontent", "adform", "openx",
    "quantserve", "quantcount", "demdex", "rfihub", "everesttech",
    "adsrvr", "casalemedia", "exoclick", "propellerads", "popads",
    "mgid", "teads", "smartadserver", "adcolony", "chartboost", "fyber",
    "inmobi", "unityads", "applovin", "ironsrc",
    "tracking", "tracker", "pixel", "beacon", "affiliate", "clk.", "click.",
]

AD_HOST_KEYWORDS: list[str] = []
AD_HOST_REGEXES               = [YT_AD_REGEX]

for _kw in AD_HOST_KEYWORDS_RAW:
    _k = (_kw or "").strip()
    if not _k:
        continue
    if ("[" in _k) or ("\\" in _k) or ("+" in _k):
        try:
            AD_HOST_REGEXES.append(re.compile(_k, re.IGNORECASE))
        except Exception:
            AD_HOST_KEYWORDS.append(_k.lower())
    else:
        AD_HOST_KEYWORDS.append(_k.lower())

keyword_blocklist = list(set([
    "ssai.",
    "scte-35", "banner", "advertisement",
    "trafficjunky.com", "media.trafficjunky.net", "ads.trafficjunky.com",
    "track.trafficjunky.com", "cdn.trafficjunky.com",
    "adtng.com", "trafficfactory", "ads.trafficfactory",
    "track.trafficfactory", "cdn.trafficfactory",
    "pb_iframe", "creatives",
    "metrics", "analytics", "telemetry", "insight", "experiment",
    "abtest", "optimize", "personalize", "audience", "segment",
    "segmentio", "snowplow", "amplitude", "mixpanel", "newrelic",
    "datadog", "app-measurement", "firebase", "measurement", "stats",
    "collect", "collector", "events", "logging", "monitor",
]))

# ══════════════════════════════════════════════════════════════════════════════
# AD DETECTION / INJECTION FLAGS
# ══════════════════════════════════════════════════════════════════════════════
DETECT_AD_MARKERS         = True
DETECT_AD_INJECTION       = True
AUTO_BLOCK_INJECTED_CNAME = True
LOG_AD_INSIGHTS           = True

AD_MARKER_KEYWORDS = [
    "scte-35", "scte35", "admarker", "ad-mark", "ad_mark",
    "adbreak", "ad-break", "ad_break", "preroll", "midroll", "postroll",
    "vast", "vpaid", "ima", "adtag", "ad-tag", "ad_tag",
    "doubleclick", "googlesyndication", "googletagmanager", "googletagservices",
    "tracking", "tracker", "telemetry", "marker", "analytics", "pixel", "beacon",
]

INJECTION_WILDCARD_WINDOW    = 300
INJECTION_WILDCARD_THRESHOLD = 25
INJECTION_WILDCARD_TTL_MAX   = 120
_injection_lock    = threading.Lock()
_injection_ip_stats: dict = {}

# ══════════════════════════════════════════════════════════════════════════════
# SSAI / MANIFEST MANIPULATION DETECTION  (NEW)
# ══════════════════════════════════════════════════════════════════════════════
# Server-Side Ad Insertion (SSAI) — also called "manifest manipulation" — stitches
# ad segments directly into MPEG-DASH (.mpd) or HLS (.m3u8) manifests at the
# server level.  Because the ad chunks arrive as part of the main video stream,
# client-side blockers usually cannot distinguish them.  However, the Ad Decision
# Server (ADS), manifest-manipulator proxy, and VAST/VPAID tag endpoints all
# require their OWN DNS lookups — which we CAN intercept here.
#
# Strategy
# ────────
# 1. SSAI_HOSTNAMES  — exact or wildcard domains known to be manifest-manipulator
#    infrastructure (Yospace, Harmonic, MediaKind, AWS MediaTailor, etc.).
# 2. SSAI_KEYWORDS   — substrings that appear in SSAI CDN / proxy hostnames.
# 3. SSAI_REGEXES    — compiled patterns for ad-stitcher node naming conventions.
# 4. MPD_PERIOD_SIGNAL_KEYWORDS — strings that appear in hostnames used to serve
#    multi-period MPD ad-insertion "Representation" segments.
# 5. SCTE35_SIGNAL_KEYWORDS — hostnames associated with SCTE-35 cue servers /
#    signaling endpoints (separate from the stream CDN).
#
# When a DNS query matches any of the above, the domain is treated as an
# SSAI_SIGNAL (weight 3.0) — high enough to exceed AD_CANDIDATE_SCORE_THRESHOLD
# on its own — and is sunk immediately if AUTO_BLOCK_DISCOVERED_IMMEDIATELY=True.

SSAI_DETECT_ENABLED = True   # master switch for all SSAI detection

# ── DELEGATION TO THE MANIFEST FILTER ────────────────────────────────────────
# With true SSAI, the ad segments and the show are served by the SAME hostname.
# That is the whole design: the stitcher hides ads behind the content CDN
# precisely so a name-based blocker cannot separate them. So a DNS-layer block
# on one of these hosts does not remove the ad — it removes the programme.
#
# The fix is a division of labour:
#   • DNS kills the hosts that ONLY do ad work — decision servers, VAST tag
#     endpoints, beacon and tracking collectors. Nothing of value is lost.
#   • manifest_filter.py handles the dual-purpose hosts, editing the .m3u8 /
#     .mpd in flight to drop the ad segments while the content flows through.
#
# Set this False only if you are not running the manifest filter and would
# rather lose playback on these services than see the stitched ads.
SSAI_DELEGATE_TO_MANIFEST_FILTER = True

# Hostnames that serve REAL VIDEO as well as stitched ads. Never sinkholed
# while delegation is on; the manifest filter cleans them instead.
SSAI_CONTENT_HOSTS: set = {
    "akamaized.net",          # enormous shared CDN — blocking the parent here
                              # takes down a large share of the video web
    "content.uplynk.com",     # Uplynk segment delivery (Disney/ABC/ESPN stack)
    "cdn.jwplayer.com",       # JW Player content delivery, not just ad calls
    "dai.google.com",         # DAI *session* manifests carry the show too
    "mediatailor.us-east-1.amazonaws.com",
    "ssai.crunchyroll.com",
    "vos360.video",
}

def _is_ssai_content_host(domain: str) -> bool:
    """True if *domain* is a host that carries real content as well as ads."""
    if not SSAI_DELEGATE_TO_MANIFEST_FILTER:
        return False
    parts = domain.split(".")
    return any(".".join(parts[i:]) in SSAI_CONTENT_HOSTS for i in range(len(parts)))

# Known SSAI / manifest-manipulator vendor hostnames (exact + parent-match)
SSAI_HOSTNAMES: set = {
    # AWS Elemental MediaTailor
    "mediatailor.us-east-1.amazonaws.com",
    "ad.us-east-1.mediatailor.amazonaws.com",
    # Yospace (server-side ad insertion for Akamai / Harmonic)
    "yospace.com", "csm.yospace.com",
    "ytp-overlay", "ytp-speedmaster-overlay",
    # Harmonic / VOS
    "harmonicinc.com", "vos360.video",
    # Brightcove / Onceux SSAI
    "onceux.com", "ssai.onceux.com",
    # JW Player / Connatix ad stitching
    "jwpltx.com", "cdn.jwplayer.com",
    # Phenix Real-Time Solutions
    "phenixrts.com",
    # Akamai sidecar / SSAI nodes
    "akamaized.net",          # broad parent — scored by SSAI keyword below too
    "ssai.akamaized.net",
    # Google DAI (Dynamic Ad Insertion) — separate from googlesyndication
    "dai.google.com", "pubads.g.doubleclick.net",
    # FreeWheel MRM
    "freewheel.tv", "adm.fwmrm.net", "cdn.freewheel.tv",
    # Comcast / NBCUniversal FreeWheel
    "fwmrm.net",
    # Verizon Media / Yahoo ConnectID
    "uplynk.com", "api.uplynk.com", "content.uplynk.com",
    # Ellation (Crunchyroll) SSAI
    "ssai.crunchyroll.com",
    # Generic SSAI SaaS
    "adstitcher.com", "stitcher.com",
    # SCTE-35 cue / signaling endpoints
    "scte.org",
}

# Substring keywords strongly associated with SSAI infrastructure hostnames
SSAI_KEYWORDS: list = [
    "ssai", "dai-", "-dai.", "adstitc", "manifest-manip",
    "adinsert", "ad-insert", "ad_insert",
    "mediatailor", "adtailor",
    "adbreak", "ad-break", "adbreaker",
    "yospace", "freewheel", "fwmrm", "uplynk",
    "vmap", "vmapurl",             # VMAP = Video Multiple Ad Playlist
    "vast-tag", "vasttag", "vast_tag",
    "vpaid-tag", "vpaidtag",
    "adpod", "ad-pod", "ad_pod",   # ad pod = clustered mid-roll group
    "multiperiod", "multi-period",
    "adperiod", "ad-period",
    "scte35", "scte-35", "cue-out", "cueout", "cuein", "cue-in",
    "stitcher", "adstitch",
    "beaconing", "adbeacon",
    "admanifest", "ad-manifest",
]

# Regex patterns for SSAI CDN node naming conventions
SSAI_REGEXES: list = [re.compile(p, re.IGNORECASE) for p in [
    # AWS MediaTailor session / tracking endpoints
    r"(^|\.)v[0-9]+\.mediatailor\.[a-z0-9-]+\.amazonaws\.com$",
    # Yospace csm subdomains: csm-e.yospace.com, csm-a2.yospace.com
    r"(^|\.)csm[-a-z0-9]*\.yospace\.com$",
    # Generic SSAI proxy pattern: ssai.<anything>.<tld>
    r"(^|\.)ssai\.[a-z0-9.-]+$",
    # Uplynk / Verizon Media ad-stitching segment hosts
    r"(^|\.)content\.uplynk\.com$",
    r"(^|\.)ads[0-9]*\.uplynk\.com$",
    # FreeWheel ad delivery CDN nodes
    r"(^|\.)cdn[0-9]*\.fwmrm\.net$",
    # Multi-period MPD ad segment path pattern embedded in hostname (rare but seen)
    r"(^|\.)(adperiod|period[0-9]+-ad)\.[a-z0-9.-]+$",
    # Google DAI session manifest hosts: dai-pa.googlevideo.com, etc.
    r"(^|\.)dai[-a-z0-9]*\.googlevideo\.com$",
    # SCTE-35 cue / signal API endpoints
    r"(^|\.)(scte35|cue-?signal|adcue)[a-z0-9-]*\.[a-z0-9.-]+$",
]]

# Additional per-log insight tracking for SSAI events
_ssai_lock             = threading.Lock()
_ssai_blocked_domains: set = set()   # domains blocked via SSAI detection

def _is_ssai_domain(domain: str) -> bool:
    """
    Returns True if *domain* matches any SSAI / manifest-manipulation signal:
      • exact match or parent-domain match in SSAI_HOSTNAMES
      • substring match in SSAI_KEYWORDS
      • regex match in SSAI_REGEXES
    """
    if not SSAI_DETECT_ENABLED:
        return False
    d = domain.strip().lower().rstrip(".")
    if not d:
        return False

    # 0. Dual-purpose host — resolve it normally and let manifest_filter.py
    #    strip the ads out of the playlist. Sinkholing here would kill the
    #    content along with the ad, which is the failure this whole feature
    #    exists to avoid.
    if _is_ssai_content_host(d):
        return False

    # 1. Exact / parent hostname match
    parts = d.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in SSAI_HOSTNAMES:
            return True

    # 2. Substring keyword match
    for kw in SSAI_KEYWORDS:
        if kw in d:
            return True

    # 3. Regex match
    for rx in SSAI_REGEXES:
        try:
            if rx.search(d):
                return True
        except Exception:
            pass

    return False

def _ssai_candidate_score(domain: str) -> float:
    """Returns SSAI signal weight if domain is an SSAI host, else 0."""
    return AD_SIGNAL_WEIGHTS["ssai_signal"] if _is_ssai_domain(domain) else 0.0

# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ══════════════════════════════════════════════════════════════════════════════
shutdown_event  = threading.Event()

discover_lock   = threading.Lock()
lists_lock      = threading.Lock()
catalog_lock    = threading.Lock()
cache_lock      = threading.Lock()

blocklist:         set = set()
allowlist:         set = set()
discovered_domains:set = set()
_up_idx: int           = 0
dns_cache: dict        = {}

# ── Client IP allowlist ───────────────────────────────────────────────────────
ip_allowlist_lock                  = threading.Lock()
allowed_client_ips: set            = set()   # exact IPs, O(1) lookup
allowed_client_networks: list      = []      # ipaddress network objects (CIDR entries, if any)

_active_clients: dict  = {}
_active_lock           = threading.Lock()
_insights_lock         = threading.Lock()

_geo_lock  = threading.Lock()
_geo_cache: dict = {}

# ── Unique ad counters ────────────────────────────────────────────────────────
_adstats_lock              = threading.Lock()
_unique_ads_detected: set  = set()
_new_ads_added_total: set  = set()
_new_ads_added_since_write:set = set()

# ── Global query counter (for terminal stats) ─────────────────────────────────
_query_counter_lock = threading.Lock()
_query_total        = 0
_query_blocked      = 0
_query_allowed      = 0
_query_cache_hits   = 0
_query_doh_hits     = 0
_query_ssai_blocked = 0   # new: dedicated SSAI block counter
_query_ip_rejected  = 0   # new: clients rejected by the IP allowlist

def _inc(counter: str, n: int = 1):
    global _query_total, _query_blocked, _query_allowed, _query_cache_hits, _query_doh_hits, _query_ssai_blocked, _query_ip_rejected
    with _query_counter_lock:
        if counter == "total":       _query_total        += n
        elif counter == "blocked":   _query_blocked      += n
        elif counter == "allowed":   _query_allowed      += n
        elif counter == "cache":     _query_cache_hits   += n
        elif counter == "doh":       _query_doh_hits     += n
        elif counter == "ssai":      _query_ssai_blocked += n
        elif counter == "ip_reject": _query_ip_rejected  += n

# ══════════════════════════════════════════════════════════════════════════════
# LOGGING HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def log_message(message: str, color: str = Fore.WHITE):
    ts = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{_c('TIMESTAMP')}{ts}{_c('RESET')} {color}{message}{_c('RESET')}")

def _now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_ad_insight(kind: str, client_ip: str, qname: str, detail: str = ""):
    if not LOG_AD_INSIGHTS:
        return
    line = f"[{_now_ts()}] {kind} | client={client_ip or 'unknown'} | host={qname} | {detail}".rstrip()
    _append_line(ad_insights_log, line)

# ══════════════════════════════════════════════════════════════════════════════
# LIVE TERMINAL STATS TICKER
# ══════════════════════════════════════════════════════════════════════════════
def _print_terminal_stats():
    """Prints a compact, color-coded stats summary directly to the terminal."""
    with _query_counter_lock:
        total       = _query_total
        blocked     = _query_blocked
        allowed     = _query_allowed
        cached      = _query_cache_hits
        doh         = _query_doh_hits
        ssai_blk    = _query_ssai_blocked
        ip_rejected = _query_ip_rejected
    with _adstats_lock:
        unique_ads = len(_unique_ads_detected)
        new_adds   = len(_new_ads_added_total)
    with _ssai_lock:
        ssai_unique = len(_ssai_blocked_domains)

    block_pct = (blocked / max(1, total)) * 100
    cache_pct = (cached  / max(1, total)) * 100

    sep   = f"{_c('TIMESTAMP')}│{_c('RESET')}"
    label = lambda k, v, c=_c('STAT_VAL'): (
        f" {_c('STAT_KEY')}{k}{_c('RESET')} {c}{v}{_c('RESET')} "
    )

    line = (
        f"\n{_c('BANNER')}┌─ AdVault Stats ──────────────────────────────────────────────┐{_c('RESET')}\n"
        f"{sep}"
        f"{label('Queries',  total)}{sep}"
        f"{label('Blocked',  f'{blocked} ({block_pct:.1f}%)', _c('STAT_BAD'))}{sep}"
        f"{label('Allowed',  allowed, _c('STAT_GOOD'))}{sep}"
        f"{label('Cache',    f'{cached} ({cache_pct:.1f}%)', _c('CACHE_HIT'))}{sep}"
        f"{label('DoH hits', doh)}{sep}"
        f"{label('IP-rejected', ip_rejected, _c('STAT_BAD'))}{sep}"
        f"\n{sep}"
        f"{label('Unique ads blocked',    unique_ads,  _c('STAT_BAD'))}{sep}"
        f"{label('New domains added',     new_adds,    _c('DISCOVERY'))}{sep}"
        f"\n{sep}"
        f"{label('SSAI/Manifest blocks',  ssai_blk,   _c('SSAI'))}{sep}"
        f"{label('Unique SSAI domains',   ssai_unique, _c('SSAI'))}{sep}"
        f"\n{_c('BANNER')}└──────────────────────────────────────────────────────────────┘{_c('RESET')}\n"
    )
    print(line)

def _terminal_stats_loop():
    while not shutdown_event.is_set():
        time.sleep(TERMINAL_STATS_INTERVAL)
        if not shutdown_event.is_set() and TERMINAL_STATS_ENABLED:
            try:
                _print_terminal_stats()
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN / IP UTILITIES
# ══════════════════════════════════════════════════════════════════════════════
def _normalize_domain(domain: str) -> str:
    d = (domain or "").strip().strip(".").lower()
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:
        pass
    return d

def is_valid_domain(domain: str) -> bool:
    domain = _normalize_domain(domain)
    return bool(re.match(r"^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$", domain))

def domain_in_set_or_parent(domain: str, s: set) -> bool:
    d = _normalize_domain(domain)
    if d in s:
        return True
    parts = d.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in s:
            return True
    return False

def is_private_or_special_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return bool(
            ip.is_private or ip.is_loopback or ip.is_multicast
            or ip.is_reserved or ip.is_link_local or ip.is_unspecified
        )
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════════
# CLIENT IP ALLOWLIST  — access control for the DNS service itself
# ══════════════════════════════════════════════════════════════════════════════
def load_ip_allowlist(path: str = None) -> None:
    """
    Load allowed_ips.txt into memory. Supports one entry per line:
      - a plain IPv4/IPv6 address  (fast-path, O(1) set lookup)
      - a CIDR range, e.g. 192.168.0.0/24  (checked against a small network list)
      - blank lines and lines starting with '#' are ignored as comments
    Safe to call again at any time (e.g. on SIGHUP) to hot-reload the list.
    """
    global allowed_client_ips, allowed_client_networks
    path = path or IP_ALLOWLIST_FILE

    ips: set = set()
    nets: list = []
    invalid = 0

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ips.add(str(ipaddress.ip_address(line)))
                except ValueError:
                    try:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        invalid += 1
    except FileNotFoundError:
        log_message(
            f"IP allowlist file not found: {path} — no clients will be permitted "
            f"until it exists.",
            _c("FATAL"),
        )

    with ip_allowlist_lock:
        allowed_client_ips     = ips
        allowed_client_networks = nets

    if invalid:
        log_message(f"IP allowlist: skipped {invalid} invalid line(s) in {path}.", _c("WARN"))
    log_message(
        f"IP allowlist loaded → {len(ips):,} address(es), {len(nets):,} CIDR range(s) from {path}.",
        _c("OK"),
    )

def is_ip_allowed(ip_str: str) -> bool:
    """O(1) fast-path against the exact-address set; falls back to a small
    CIDR scan only if the allowlist actually contains any ranges."""
    if not IP_ALLOWLIST_ENABLED:
        return True
    if not ip_str:
        return False

    with ip_allowlist_lock:
        ips  = allowed_client_ips
        nets = allowed_client_networks

    if ip_str in ips:
        return True
    if not nets:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip_obj in net for net in nets)

# ══════════════════════════════════════════════════════════════════════════════
# FILE I/O HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def atomic_write(path: str, data: str):
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path) or ".")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        try:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def atomic_write_lines(path: str, items: set):
    atomic_write(path, "".join(sorted(d + "\n" for d in items)))

def _append_line(path: str, line: str):
    try:
        with _insights_lock:
            with open(path, "a", encoding="utf-8", errors="replace") as f:
                f.write(line.rstrip("\n") + "\n")
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
# ENTROPY / RANDOMNESS HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    ent = 0.0
    for _, v in c.items():
        p = v / n
        ent -= p * math.log2(p)
    return ent

def looks_like_random_subdomain(domain: str) -> bool:
    d = _normalize_domain(domain)
    parts = d.split(".")
    if len(parts) < 3:
        return False
    left = parts[0]
    if len(left) < 14:
        return False
    ent         = _shannon_entropy(left)
    digit_ratio = sum(ch.isdigit() for ch in left) / max(1, len(left))
    vowel_ratio = sum(ch in "aeiou"  for ch in left) / max(1, len(left))
    if ent >= 3.2 and digit_ratio >= 0.20:
        return True
    if ent >= 3.5 and vowel_ratio <= 0.20:
        return True
    return False

# ══════════════════════════════════════════════════════════════════════════════
# WEIGHTED AD CANDIDATE SCORING
# ══════════════════════════════════════════════════════════════════════════════
def _keyword_in_domain_with_boundaries(keyword: str, domain: str) -> bool:
    """Boundary-aware match for short tokens to avoid false positives."""
    k = (keyword or "").lower().strip()
    d = _normalize_domain(domain)
    if not k or not d:
        return False
    if len(k) <= SHORT_MARKER_MAXLEN:
        pat = re.compile(rf"(^|[._-]){re.escape(k)}($|[._-])")
        return bool(pat.search(d))
    return k in d

def _ad_candidate_score(domain: str) -> float:
    """
    Returns a numeric score representing how likely `domain` is an ad/tracker/SSAI host.
    Score >= AD_CANDIDATE_SCORE_THRESHOLD  →  treat as candidate.
    """
    d = _normalize_domain(domain)
    if not d:
        return 0.0

    score = 0.0

    # SSAI / manifest-manipulation check (highest priority signal, checked first)
    ssai_score = _ssai_candidate_score(d)
    if ssai_score > 0:
        score += ssai_score
        # SSAI score alone exceeds threshold — skip remaining checks for speed
        return score

    # Regex patterns
    for rx in AD_HOST_REGEXES:
        try:
            if rx.search(d):
                score += AD_SIGNAL_WEIGHTS["regex_match"]
                break
        except Exception:
            pass

    # Substring keyword patterns
    for kw in AD_HOST_KEYWORDS:
        if kw and kw in d:
            score += AD_SIGNAL_WEIGHTS["keyword_match"]
            break

    # AD marker keywords (boundary-aware)
    for kw in AD_MARKER_KEYWORDS:
        if _keyword_in_domain_with_boundaries(kw, d):
            score += AD_SIGNAL_WEIGHTS["marker_keyword"]
            break

    # Randomish subdomain
    if looks_like_random_subdomain(d):
        score += AD_SIGNAL_WEIGHTS["randomish"]

    # Suspicious TLD
    for tld in AD_SUSPICIOUS_TLDS:
        if d.endswith(tld):
            score += AD_SIGNAL_WEIGHTS["tld_suspicious"]
            break

    return score

def hostname_is_ad_candidate(domain: str) -> bool:
    return _ad_candidate_score(domain) >= AD_CANDIDATE_SCORE_THRESHOLD

# ══════════════════════════════════════════════════════════════════════════════
# AD STATS HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _record_unique_ad_detected(domain: str):
    d = _normalize_domain(domain)
    if not d:
        return
    with _adstats_lock:
        _unique_ads_detected.add(d)

def _record_new_ad_added(domain: str):
    d = _normalize_domain(domain)
    if not d:
        return
    with _adstats_lock:
        _new_ads_added_total.add(d)
        _new_ads_added_since_write.add(d)
        _unique_ads_detected.add(d)

def _record_ssai_blocked(domain: str):
    d = _normalize_domain(domain)
    if not d:
        return
    with _ssai_lock:
        _ssai_blocked_domains.add(d)

# ══════════════════════════════════════════════════════════════════════════════
# DNS RECORD HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _collect_cname_targets(dnsrec: DNSRecord) -> list:
    targets = []
    try:
        sections = (
            list(getattr(dnsrec, "rr",   []))
            + list(getattr(dnsrec, "auth", []))
            + list(getattr(dnsrec, "ar",   []))
        )
        for rr in sections:
            try:
                if rr.rtype == QTYPE.CNAME:
                    t = _normalize_domain(str(rr.rdata.label))
                    if t:
                        targets.append(t)
            except Exception:
                pass
    except Exception:
        pass
    return targets

def _collect_a_aaaa_answers(dnsrec: DNSRecord) -> list:
    ips = []
    try:
        for rr in list(getattr(dnsrec, "rr", [])):
            try:
                if rr.rtype == QTYPE.A:
                    ips.append((str(rr.rdata), rr.ttl))
                elif rr.rtype == QTYPE.AAAA:
                    ips.append((str(rr.rdata), rr.ttl))
            except Exception:
                pass
    except Exception:
        pass
    return ips

# ══════════════════════════════════════════════════════════════════════════════
# INJECTION / WILDCARD TRACKING
# ══════════════════════════════════════════════════════════════════════════════
def _track_possible_wildcard_injection(qname: str, ips_with_ttl: list, client_ip: str):
    if not ips_with_ttl:
        return
    d = _normalize_domain(qname)
    if not looks_like_random_subdomain(d):
        return
    ip, ttl = ips_with_ttl[0]
    if ttl is None:
        ttl = 0
    if ttl > INJECTION_WILDCARD_TTL_MAX:
        return

    now = time.time()
    with _injection_lock:
        st = _injection_ip_stats.get(ip)
        if not st:
            st = {"first": now, "last": now, "names": set()}
            _injection_ip_stats[ip] = st
        st["last"] = now
        st["names"].add(d)

        cutoff = now - INJECTION_WILDCARD_WINDOW
        for k in list(_injection_ip_stats.keys()):
            if _injection_ip_stats[k]["last"] < cutoff:
                _injection_ip_stats.pop(k, None)

        if len(st["names"]) >= INJECTION_WILDCARD_THRESHOLD:
            detail = (
                f"suspected_wildcard_or_hijack ip={ip} "
                f"distinct_randomish={len(st['names'])} "
                f"ttl<={INJECTION_WILDCARD_TTL_MAX}"
            )
            log_message(f"AD INJECTION SUSPECT (wildcard/hijack): {detail}", _c("INJECTION"))
            log_ad_insight("INJECTION_WILDCARD", client_ip, d, detail)

# ══════════════════════════════════════════════════════════════════════════════
# GEO HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _geo_cache_get(ip: str):
    now = time.time()
    with _geo_lock:
        v = _geo_cache.get(ip)
        if not v:
            return None
        exp, cc = v
        if exp < now:
            _geo_cache.pop(ip, None)
            return None
        return cc

def _geo_cache_put(ip: str, cc: str):
    with _geo_lock:
        _geo_cache[ip] = (time.time() + float(GEO_CACHE_TTL), cc)

def geo_country_for_ip(ip: str) -> str:
    if not GEO_ENABLED or not ip or ip == "unknown":
        return "DEFAULT"
    if is_private_or_special_ip(ip):
        return "DEFAULT"
    cached = _geo_cache_get(ip)
    if cached:
        return cached
    cc = "DEFAULT"
    try:
        if not GEO_LOOKUP_URL or "{ip}" not in GEO_LOOKUP_URL:
            return "DEFAULT"
        url = GEO_LOOKUP_URL.format(ip=ip)
        r   = requests.get(url, timeout=float(GEO_LOOKUP_TIMEOUT))
        data = r.json() if r is not None else {}
        if data.get("status") == "success":
            cc = (data.get("countryCode") or "DEFAULT").upper()
    except Exception:
        cc = "DEFAULT"
    _geo_cache_put(ip, cc)
    return cc

def _best_geo_rule_match(qname: str, rules_dict: dict):
    q = _normalize_domain(qname)
    best, best_len = None, -1
    for k in rules_dict.keys():
        kk = _normalize_domain(k)
        if q == kk or q.endswith("." + kk):
            if len(kk) > best_len:
                best, best_len = kk, len(kk)
    return best

def geo_override_answer(request: DNSRecord, client_ip: str):
    qname = _normalize_domain(str(request.q.qname))
    qtype = int(request.q.qtype)

    if qtype == QTYPE.A and GEO_SPOOF_RULES_A:
        key = _best_geo_rule_match(qname, GEO_SPOOF_RULES_A)
        if key:
            cc = geo_country_for_ip(client_ip)
            ip = (GEO_SPOOF_RULES_A.get(key, {}).get(cc)
                  or GEO_SPOOF_RULES_A.get(key, {}).get("DEFAULT"))
            if ip:
                reply = request.reply()
                reply.header.rcode = RCODE.NOERROR
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
                log_message(f"GEO OVERRIDE (A): {qname} | client={client_ip} ({cc}) -> {ip}", _c("GEO"))
                return reply.pack()

    if qtype == QTYPE.AAAA and GEO_SPOOF_RULES_AAAA:
        key = _best_geo_rule_match(qname, GEO_SPOOF_RULES_AAAA)
        if key:
            cc  = geo_country_for_ip(client_ip)
            ip6 = (GEO_SPOOF_RULES_AAAA.get(key, {}).get(cc)
                   or GEO_SPOOF_RULES_AAAA.get(key, {}).get("DEFAULT"))
            if ip6:
                reply = request.reply()
                reply.header.rcode = RCODE.NOERROR
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(ip6), ttl=60))
                log_message(f"GEO OVERRIDE (AAAA): {qname} | client={client_ip} ({cc}) -> {ip6}", _c("GEO"))
                return reply.pack()

    return None

# ══════════════════════════════════════════════════════════════════════════════
# ACTIVE CLIENT / IP TRACKING
# ══════════════════════════════════════════════════════════════════════════════
def _init_ip_state(now: float, sec: int, W: int):
    return {
        "last": now, "base_sec": sec,
        "ring":       [0] * max(1, W), "ring_sum":      0,
        "ring_rand":  [0] * max(1, W), "ring_rand_sum": 0,
        "total": 0, "sample_mod": 0,
        "sample": deque(maxlen=SAMPLE_MAX_ITEMS_PER_IP),
    }

def mark_active_ip(ip: str, qname: str):
    if not ip:
        return
    now     = time.time()
    sec     = int(now)
    W       = max(1, int(USERS_ACTIVE_WINDOW))
    randish = 1 if looks_like_random_subdomain(qname) else 0

    with _active_lock:
        st = _active_clients.get(ip)
        if not st or len(st.get("ring", [])) != W:
            st = _init_ip_state(now, sec, W)
            _active_clients[ip] = st

        delta = sec - int(st["base_sec"])
        if delta >= W:
            st["ring"]      = [0] * W; st["ring_sum"]      = 0
            st["ring_rand"] = [0] * W; st["ring_rand_sum"] = 0
            st["base_sec"]  = sec
        elif delta > 0:
            for i in range(1, delta + 1):
                idx = (int(st["base_sec"]) + i) % W
                st["ring_sum"]      -= st["ring"][idx];      st["ring"][idx]      = 0
                st["ring_rand_sum"] -= st["ring_rand"][idx]; st["ring_rand"][idx] = 0
            st["base_sec"] = sec

        idx = sec % W
        st["ring"][idx] += 1; st["ring_sum"] += 1
        if randish:
            st["ring_rand"][idx] += 1; st["ring_rand_sum"] += 1
        st["last"]  = now
        st["total"] = int(st.get("total", 0)) + 1
        st["sample_mod"] = (int(st.get("sample_mod", 0)) + 1) % max(1, int(SAMPLE_EVERY_N_QUERIES))
        if st["sample_mod"] == 0:
            st["sample"].append(_normalize_domain(qname))

def _prune_and_snapshot(now=None):
    if now is None:
        now = time.time()
    cutoff = now - float(USERS_ACTIVE_WINDOW)
    with _active_lock:
        stale = [ip for ip, st in _active_clients.items()
                 if float(st.get("last", 0.0)) < cutoff]
        for ip in stale:
            _active_clients.pop(ip, None)
        snap = {}
        for ip, st in _active_clients.items():
            snap[ip] = {
                "last":   float(st.get("last", 0.0)),
                "q_win":  int(st.get("ring_sum", 0)),
                "r_win":  int(st.get("ring_rand_sum", 0)),
                "total":  int(st.get("total", 0)),
                "sample": list(st.get("sample", [])),
            }
        return snap

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD FILE WRITER
# ══════════════════════════════════════════════════════════════════════════════
def _snapshot_ad_stats_for_dashboard():
    with _adstats_lock:
        total_unique_ads = len(_unique_ads_detected)
        total_new_added  = len(_new_ads_added_total)
        new_since_write  = len(_new_ads_added_since_write)
        _new_ads_added_since_write.clear()
    return total_unique_ads, total_new_added, new_since_write

def write_current_users_periodically():
    while not shutdown_event.is_set():
        try:
            now  = time.time()
            W    = max(1, int(USERS_ACTIVE_WINDOW))
            snap = _prune_and_snapshot(now)
            unique_networks = len(snap)
            total_unique_ads, total_new_added, new_since_write = _snapshot_ad_stats_for_dashboard()
            with _ssai_lock:
                ssai_count = len(_ssai_blocked_domains)

            lines = [
                f"Current unique networks: {unique_networks}",
                f"Total unique ads detected (this run): {total_unique_ads}",
                f"Total newly detected ads added (this run): {total_new_added}",
                f"Newly detected ads added (since last update): {new_since_write}",
                f"SSAI/Manifest-manipulation domains blocked: {ssai_count}",
                f"Updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Active window: {USERS_ACTIVE_WINDOW}s  |  Write interval: {USERS_WRITE_INTERVAL}s",
                "",
                f"Active client IPs (last {USERS_ACTIVE_WINDOW}s):",
                "IP\tq\tqps\trand%\tuniq~\tseen\tflags",
            ]

            for ip, st in sorted(snap.items(), key=lambda x: (-x[1]["q_win"], -x[1]["last"], x[0])):
                age        = max(0.0, now - float(st["last"]))
                q_win      = int(st["q_win"])
                qps        = q_win / float(W)
                r_win      = int(st["r_win"])
                rand_ratio = r_win / max(1, q_win)
                sample     = st.get("sample", [])
                approx_uniq = len(set(sample)) if sample else 0
                flags = []
                if qps        >= HOT_QPS_THRESHOLD:         flags.append("HOT")
                if q_win >= 50 and rand_ratio >= RANDOMISH_RATIO_THRESHOLD: flags.append("RANDOMISH")
                lines.append(
                    f"{ip}\tq={q_win}\t{qps:.1f}\t{rand_ratio*100:.0f}%"
                    f"\t{approx_uniq}\t{age:.1f}s\t{','.join(flags) or '-'}"
                )

            atomic_write(USERS_FILE, "\n".join(lines) + "\n")

        except Exception as e:
            log_message(f"User/client write fail: {e}", _c("WARN"))

        time.sleep(USERS_WRITE_INTERVAL)

# ══════════════════════════════════════════════════════════════════════════════
# AD MARKER / INJECTION DETECTION
# ══════════════════════════════════════════════════════════════════════════════
def detect_ad_markers(client_ip: str, qname: str, qtype: int):
    if not DETECT_AD_MARKERS:
        return
    d          = _normalize_domain(qname)
    qtype_name = QTYPE.get(qtype, str(qtype))

    # Check for SSAI signal first (new)
    if _is_ssai_domain(d):
        detail = f"ssai_manifest_manipulator qtype={qtype_name}"
        log_message(f"SSAI/MANIFEST SIGNAL: {d} ({detail})", _c("SSAI"))
        log_ad_insight("SSAI_SIGNAL", client_ip, d, detail)

    marker_hits = [kw.lower() for kw in AD_MARKER_KEYWORDS
                   if _keyword_in_domain_with_boundaries(kw, d)]
    host_hits   = [kw for kw in AD_HOST_KEYWORDS if kw and kw in d]

    for rx in AD_HOST_REGEXES:
        try:
            if rx.search(d):
                host_hits.append(f"regex:{rx.pattern}")
        except Exception:
            pass

    if marker_hits:
        detail = f"markers={','.join(sorted(set(marker_hits)))} qtype={qtype_name}"
        log_message(f"AD MARKER SIGNAL: {d} ({detail})", _c("AD_SIGNAL"))
        log_ad_insight("AD_MARKER", client_ip, d, detail)

    if host_hits:
        detail = f"host_keywords={','.join(sorted(set(host_hits)))} qtype={qtype_name}"
        log_message(f"AD HOST SIGNAL: {d} ({detail})", _c("AD_SIGNAL"))
        log_ad_insight("AD_HOST_SIGNAL", client_ip, d, detail)

    if looks_like_random_subdomain(d):
        log_ad_insight("RANDOMISH_HOST", client_ip, d, f"randomish_subdomain qtype={qtype_name}")

def detect_and_mitigate_ad_injection(request: DNSRecord, parsed_reply: DNSRecord, client_ip: str):
    if not DETECT_AD_INJECTION:
        return None

    qname = _normalize_domain(str(request.q.qname))
    qtype = request.q.qtype

    for t in _collect_cname_targets(parsed_reply):
        if domain_in_set_or_parent(t, allowlist_critical) or domain_in_set_or_parent(t, allowlist):
            continue
        is_target_blocked   = is_blocked(t)
        is_target_candidate = hostname_is_ad_candidate(t)

        if is_target_blocked or is_target_candidate:
            kind   = "INJECTION_CNAME_BLOCKED" if is_target_blocked else "INJECTION_CNAME_CANDIDATE"
            detail = f"cname_target={t} qtype={QTYPE.get(qtype, str(qtype))}"
            log_message(f"AD INJECTION SIGNAL: {qname} -> CNAME {t}", _c("INJECTION"))
            log_ad_insight(kind, client_ip, qname, detail)

            if is_target_candidate and not is_target_blocked:
                try: catalog_candidate(t)
                except Exception: pass
                try: add_discovered_domain(t)
                except Exception: pass

            if AUTO_BLOCK_INJECTED_CNAME:
                log_message(f"INJECTION MITIGATED (sunk): {qname} (via {t})", _c("INJECTION"))
                log_ad_insight("INJECTION_SUNK", client_ip, qname, f"via_cname={t}")
                # Fast-fail: answers every qtype, negative-cacheable, no hang.
                return build_block_reply(request, qname)
            break

    ips_with_ttl = _collect_a_aaaa_answers(parsed_reply)
    _track_possible_wildcard_injection(qname, ips_with_ttl, client_ip)

    for ip, ttl in ips_with_ttl[:4]:
        if is_private_or_special_ip(ip):
            log_ad_insight("SPECIAL_IP_ANSWER", client_ip, qname, f"special_ip_answer ip={ip} ttl={ttl}")

    return None

# ══════════════════════════════════════════════════════════════════════════════
# FILE I/O  — domains, catalog
# ══════════════════════════════════════════════════════════════════════════════
def load_file_domains(file_path: str) -> set:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            out = set()
            for line in f:
                d = _normalize_domain(line)
                if is_valid_domain(d):
                    out.add(d)
            return out
    except FileNotFoundError:
        return set()

def save_domains(file_path: str, domains: set):
    try:
        atomic_write_lines(file_path, domains)
    except Exception as e:
        log_message(f"Error saving {file_path}: {e}", _c("ERROR"))

def load_catalog() -> dict:
    try:
        with open(catalog_file, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return {}

def save_catalog(cat: dict):
    try:
        atomic_write(catalog_file, json.dumps(cat, ensure_ascii=False, indent=2))
    except Exception as e:
        log_message(f"Error saving {catalog_file}: {e}", _c("ERROR"))

# ══════════════════════════════════════════════════════════════════════════════
# HTTP SESSION  (blocklist fetches + DoH)
# ══════════════════════════════════════════════════════════════════════════════
http_session = requests.Session()
http_session.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":     "*/*",
    "Connection": "close",
})

def fetch_blocklist(url: str) -> str:
    try:
        r = http_session.get(url, timeout=10)
        r.raise_for_status()
        return r.text
    except requests.exceptions.RequestException as e:
        log_message(f"Failed to fetch blocklist from {url}: {e}", _c("WARN"))
        return ""

def parse_blocklist(raw_data: str) -> set:
    """Handles plain domains, ABP ||domain^, and hosts-file 0.0.0.0 domain lines."""
    domains = set()
    for line in raw_data.splitlines():
        line = line.strip()
        if not line or line[0] in ("#", "!", "["):
            continue
        domain = ""
        if line[0].isdigit() and " " in line and not line.startswith("||"):
            parts  = line.split()
            domain = parts[1] if len(parts) >= 2 else ""
        elif line.startswith("||"):
            domain = line[2:].split("^", 1)[0].strip()
        elif "$" in line:
            m = re.search(r"domain=([a-zA-Z0-9.-]+)", line)
            domain = m.group(1) if m else ""
        else:
            domain = line
        domain = _normalize_domain(domain)
        if is_valid_domain(domain):
            domains.add(domain)
    return domains

# ══════════════════════════════════════════════════════════════════════════════
# DNS-OVER-HTTPS UPSTREAM
# ══════════════════════════════════════════════════════════════════════════════
_doh_session = requests.Session()
_doh_session.headers.update({
    "Accept":       "application/dns-message",
    "Content-Type": "application/dns-message",
    "User-Agent":   "AdVaultDNS/3.0",
})

def _next_doh_url() -> str:
    global _doh_idx
    with _doh_idx_lock:
        url      = DOH_UPSTREAMS[_doh_idx % len(DOH_UPSTREAMS)]
        _doh_idx += 1
    return url

def _doh_query(query_bytes: bytes) -> bytes | None:
    """
    Send a DNS wire-format query via DNS-over-HTTPS (RFC 8484 POST).
    Returns raw DNS wire-format response bytes, or None on failure.
    """
    if not DOH_ENABLED or not DOH_UPSTREAMS:
        return None
    url = _next_doh_url()
    try:
        resp = _doh_session.post(
            url,
            data    = query_bytes,
            timeout = DOH_TIMEOUT,
            headers = {"Content-Type": "application/dns-message",
                       "Accept":       "application/dns-message"},
        )
        if resp.status_code == 200:
            _inc("doh")
            return resp.content
    except Exception as e:
        log_message(f"DoH query failed ({url}): {e}", _c("WARN"))
    return None

# ══════════════════════════════════════════════════════════════════════════════
# BLOCK / ALLOW LIST MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════
def compact_discovered_blocklist():
    discovered = load_file_domains(discovered_file)
    if discovered:
        save_domains(discovered_file, discovered)
        log_message(f"Compacted discovered list to {len(discovered)} domains.", _c("INFO"))

def update_blocklist_preserve():
    with lists_lock:
        existing  = load_file_domains(blocklist_file)
        collected = set(existing)

        for url in blocklist_urls:
            log_message(f"Fetching blocklist: {url}", _c("INFO"))
            raw = fetch_blocklist(url)
            if raw:
                ds = parse_blocklist(raw)
                log_message(f"  └─ Extracted {len(ds)} valid domains.", _c("OK"))
                collected.update(ds)

        local_discovered = load_file_domains(discovered_file)
        if local_discovered:
            log_message(f"Including {len(local_discovered)} locally discovered domains.", _c("DISCOVERY"))
            collected.update(local_discovered)

        save_domains(blocklist_file, collected)
        log_message(f"Blocklist updated → {len(collected)} total domains (no deletions).", _c("OK"))

def load_lists_into_memory():
    global blocklist, allowlist, discovered_domains
    with lists_lock:
        blocklist          = load_file_domains(blocklist_file)
        allowlist          = load_file_domains(allowlist_file)
        discovered_domains = load_file_domains(discovered_file)
        blocklist.update(discovered_domains)
    log_message(
        f"In-memory lists → block={len(blocklist):,}  "
        f"allow={len(allowlist):,}  discovered={len(discovered_domains):,}",
        _c("INFO"),
    )

# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN DISCOVERY & BLOCKING
# ══════════════════════════════════════════════════════════════════════════════
def catalog_candidate(domain: str):
    d = _normalize_domain(domain)
    if not is_valid_domain(d):
        return
    if domain_in_set_or_parent(d, allowlist_critical) or domain_in_set_or_parent(d, allowlist):
        return
    if d in blocklist:
        return
    with catalog_lock:
        cat = load_catalog()
        now = int(time.time())
        if d not in cat:
            cat[d] = {"count": 1, "first": now, "last": now,
                      "score": round(_ad_candidate_score(d), 2)}
        else:
            cat[d]["count"] += 1
            cat[d]["last"]   = now
        save_catalog(cat)

def add_discovered_domain(domain: str) -> bool:
    d = _normalize_domain(domain)
    if not is_valid_domain(d):
        return False
    if domain_in_set_or_parent(d, allowlist_critical) or domain_in_set_or_parent(d, allowlist):
        return False
    with discover_lock:
        if d in discovered_domains or d in blocklist:
            return False
        discovered_domains.add(d)
        if AUTO_ADD_DISCOVERED_TO_BLOCKLIST:
            blocklist.add(d)
        _append_line(discovered_file, d)
        _record_new_ad_added(d)

    score = _ad_candidate_score(d)
    log_message(f"Discovered ad domain added: {d}  (score={score:.1f})", _c("DISCOVERY"))
    return True

def is_blocked(domain: str) -> bool:
    d = _normalize_domain(domain)
    if domain_in_set_or_parent(d, allowlist_critical) or domain_in_set_or_parent(d, allowlist):
        return False
    if d in blocklist:
        return True
    for kw in keyword_blocklist:
        if kw and kw in d:
            return True
    return False

# ══════════════════════════════════════════════════════════════════════════════
# DNS CACHE
# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# FAST-FAIL BLOCK RESPONSES
#
# A blocked lookup must fail *immediately* and *completely*. Every millisecond
# a player spends waiting on a blocked ad call is a millisecond its buffer
# drains. The three failure modes that cause stalls, all fixed here:
#
#   1. Slow failure  — sinkholing to a routable IP means the client waits out
#                      a full TCP connect timeout. Fixed by 0.0.0.0 / ::.
#   2. Silent NODATA — returning NOERROR with an empty answer and no authority
#                      section gives the stub nothing to cache, so it re-queries
#                      on every segment boundary and may wait out its own timer.
#                      Fixed by always attaching an SOA.
#   3. Half answers  — answering A but leaving AAAA (or HTTPS/SVCB, qtype 65,
#                      which modern players query first) unanswered strands
#                      dual-stack clients in Happy Eyeballs fallback timers.
#                      Fixed by answering every qtype authoritatively.
# ══════════════════════════════════════════════════════════════════════════════
def _soa_zone_for(qname: str) -> str:
    """
    Pick a plausible zone name to own the SOA record. Stub resolvers key their
    negative cache off this, so it should be the registrable domain rather than
    the full queried name — that way one blocked lookup suppresses re-queries
    for sibling hostnames in the same ad zone too.
    """
    labels = qname.strip(".").split(".")
    if len(labels) <= 2:
        return qname.strip(".") or "."
    last_two = ".".join(labels[-2:])
    if last_two in _TWO_PART_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _attach_block_soa(reply, qname: str, ttl: int = None):
    """
    Attach an SOA to the authority section so the client negative-caches the
    failure for BLOCK_NEGATIVE_TTL instead of re-asking every few seconds.
    Per RFC 2308 the effective negative TTL is min(SOA.ttl, SOA.minimum).
    """
    ttl  = BLOCK_NEGATIVE_TTL if ttl is None else ttl
    zone = _soa_zone_for(qname)
    try:
        reply.add_auth(RR(
            zone, QTYPE.SOA, ttl=ttl,
            rdata=SOA(
                mname="localhost.",
                rname="advault.localhost.",
                times=(
                    int(time.time()),   # serial
                    3600,               # refresh
                    600,                # retry
                    86400,              # expire
                    ttl,                # minimum → the negative TTL
                ),
            ),
        ))
    except Exception as e:
        # Never let SOA construction turn a fast block into a resolver error.
        log_message(f"SOA attach failed for {qname}: {e}", _c("WARN"))
    return reply


def build_block_reply(request, qname: str, mode: str = None, ttl: int = 60) -> bytes:
    """
    Build a complete, fast-failing response for a blocked domain.

    Answers EVERY query type authoritatively — no silent NODATA, no unanswered
    AAAA or HTTPS record leaving the client on a timer. Returns packed wire
    bytes ready to send.
    """
    mode  = (mode or BLOCK_MODE).lower()
    qtype = request.q.qtype
    reply = request.reply()

    if mode == "refused":
        reply.header.rcode = RCODE.REFUSED
        return reply.pack()

    if mode == "null":
        # NOERROR plus an unspecified address: the connect() fails instantly
        # in the local stack without a packet ever leaving the machine.
        reply.header.rcode = RCODE.NOERROR
        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(SINK_IPv4), ttl=ttl))
        elif qtype == QTYPE.AAAA:
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(SINK_IPv6), ttl=ttl))
        else:
            # Every other type (HTTPS/SVCB 65, TXT, SRV, ...) gets an explicit
            # authoritative NODATA so the client stops waiting and stops asking.
            _attach_block_soa(reply, qname, ttl)
        return reply.pack()

    # Default: NXDOMAIN + SOA — the cleanest, fastest signal for a video player.
    reply.header.rcode = RCODE.NXDOMAIN
    _attach_block_soa(reply, qname, ttl)
    return reply.pack()


def cache_get(qname: str, qtype: int):
    k = (qname, qtype)
    with cache_lock:
        v = dns_cache.get(k)
        if not v:
            return None
        exp, blob = v
        if exp < time.time():
            dns_cache.pop(k, None)
            return None
        return blob

def cache_put(qname: str, qtype: int, reply: DNSRecord):
    try:
        ttls = [rr.ttl for rr in reply.rr if str(rr.rname).strip(".").lower() == qname]
        ttl  = max(5, min(CACHE_TTL_CAP, min(ttls) if ttls else 30))
        blob = reply.pack()
        with cache_lock:
            if len(dns_cache) > CACHE_MAX_ENTRIES:
                dns_cache.clear()
            dns_cache[(qname, qtype)] = (time.time() + ttl, blob)
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════════
# CORE RESOLUTION  — DoH first, UDP/TCP fallback
# ══════════════════════════════════════════════════════════════════════════════
def _next_upstream():
    global _up_idx
    up      = UPSTREAMS[_up_idx % len(UPSTREAMS)]
    _up_idx += 1
    return up

def _recv_exact(sock, n: int):
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            return None
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)

def _udp_query(query_bytes: bytes) -> bytes:
    up = _next_upstream()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(UPSTREAM_UDP_TIMEOUT)
        s.sendto(query_bytes, up)
        resp, _ = s.recvfrom(65535)
        return resp

def _tcp_query(query_bytes: bytes):
    up = _next_upstream()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(UPSTREAM_TCP_TIMEOUT)
        s.connect(up)
        s.sendall(struct.pack("!H", len(query_bytes)) + query_bytes)
        lp = _recv_exact(s, 2)
        if not lp:
            return None
        (msg_len,) = struct.unpack("!H", lp)
        return _recv_exact(s, msg_len)

def resolve_query(query_bytes: bytes, client_ip: str = None) -> bytes:
    try:
        request = DNSRecord.parse(query_bytes)
        qname   = _normalize_domain(str(request.q.qname))
        qtype   = request.q.qtype

        mark_active_ip(client_ip or "unknown", qname)
        _inc("total")

        if GEO_OVERRIDE_PRECEDENCE_BEFORE_BLOCKING:
            geo_resp = geo_override_answer(request, client_ip or "unknown")
            if geo_resp:
                return geo_resp

        log_message(f"Query: {qname} [{QTYPE.get(qtype, qtype)}]", _c("QUERY"))
        detect_ad_markers(client_ip or "unknown", qname, qtype)

        # ── SSAI / Manifest-manipulation check (new — runs before normal block) ─
        if SSAI_DETECT_ENABLED and _is_ssai_domain(qname):
            if not domain_in_set_or_parent(qname, allowlist_critical) and \
               not domain_in_set_or_parent(qname, allowlist):
                _inc("blocked")
                _inc("ssai")
                _record_unique_ad_detected(qname)
                _record_ssai_blocked(qname)
                # Auto-add to discovered so it persists across restarts
                add_discovered_domain(qname)
                log_message(
                    f"SSAI BLOCKED  {qname}  [manifest-manipulator / ad-stitcher]",
                    _c("SSAI"),
                )
                log_ad_insight("SSAI_BLOCKED", client_ip or "unknown", qname,
                               f"qtype={QTYPE.get(qtype, str(qtype))}")
                # Fast-fail: answers every qtype, negative-cacheable, no hang.
                return build_block_reply(request, qname)

        if hostname_is_ad_candidate(qname):
            catalog_candidate(qname)

        # ── Block check ───────────────────────────────────────────────────────
        if is_blocked(qname):
            _record_unique_ad_detected(qname)
            _inc("blocked")
            log_message(f"BLOCKED  {qname}", _c("BLOCKED"))
            log_ad_insight("BLOCKED", client_ip or "unknown", qname,
                           f"qtype={QTYPE.get(qtype, str(qtype))}")
            # Fast-fail: answers every qtype, negative-cacheable, no hang.
            return build_block_reply(request, qname)

        _inc("allowed")
        log_message(f"ALLOWED  {qname}", _c("ALLOWED"))

        if not GEO_OVERRIDE_PRECEDENCE_BEFORE_BLOCKING:
            geo_resp = geo_override_answer(request, client_ip or "unknown")
            if geo_resp:
                return geo_resp

        # ── Cache check ───────────────────────────────────────────────────────
        cached = cache_get(qname, qtype)
        if cached:
            _inc("cache")
            log_message(f"CACHE HIT  {qname}", _c("CACHE_HIT"))
            return cached

        # ── Upstream resolution: DoH → UDP → TCP ─────────────────────────────
        resp   = None
        errors = []

        # 1) Try DoH first
        resp = _doh_query(query_bytes)
        if resp:
            try:
                DNSRecord.parse(resp)   # validate
            except Exception as e:
                log_message(f"DoH response parse error: {e}", _c("WARN"))
                resp = None

        # 2) Fall back to UDP / TCP
        if not resp:
            for _ in range(len(UPSTREAMS)):
                try:
                    resp   = _udp_query(query_bytes)
                    parsed = DNSRecord.parse(resp)
                    if parsed.header.tc == 1:
                        raise ValueError("TC bit set — upgrading to TCP")
                    break
                except Exception as e_udp:
                    errors.append(f"UDP: {e_udp}")
                    try:
                        resp = _tcp_query(query_bytes)
                        if resp:
                            break
                    except Exception as e_tcp:
                        errors.append(f"TCP: {e_tcp}")

        if not resp:
            log_message(f"All upstreams failed for {qname}: {errors}", _c("ERROR"))
            raise Exception("All upstreams failed")

        parsed   = DNSRecord.parse(resp)
        override = detect_and_mitigate_ad_injection(request, parsed, client_ip or "unknown")
        if override:
            return override

        # ── Auto-evolve: add newly discovered ad domains ───────────────────────
        if hostname_is_ad_candidate(qname) and not is_blocked(qname):
            added = add_discovered_domain(qname)
            if added and AUTO_BLOCK_DISCOVERED_IMMEDIATELY:
                _record_unique_ad_detected(qname)
                log_message(f"AUTO-BLOCKED (immediate): {qname}", _c("AUTO_BLOCK"))
                log_ad_insight("AUTO_BLOCK_IMMEDIATE", client_ip or "unknown", qname,
                               f"qtype={QTYPE.get(qtype, str(qtype))}")
                # Fast-fail: answers every qtype, negative-cacheable, no hang.
                return build_block_reply(request, qname)

        cache_put(qname, qtype, parsed)
        log_message(f"RESOLVED  {qname}", _c("RESOLVED"))
        return resp

    except Exception as e:
        log_message(f"Resolver error: {e}", _c("ERROR"))
        try:
            req      = DNSRecord.parse(query_bytes)
            servfail = req.reply()
            servfail.header.rcode = RCODE.SERVFAIL
            return servfail.pack()
        except Exception:
            return b""

# ══════════════════════════════════════════════════════════════════════════════
# DNS SERVERS  — UDP, TCP, DoT
# ══════════════════════════════════════════════════════════════════════════════
def _udp_handle_one(sock, data, addr):
    try:
        response = resolve_query(data, client_ip=addr[0])
        if response:
            sock.sendto(response, addr)
    except Exception as e:
        log_message(f"UDP handle error: {e}", _c("WARN"))

def start_udp_server(host=LISTEN_HOST, port=DNS_UDP_PORT, workers=UDP_WORKERS):
    log_message(f"Starting DNS (UDP) on {host}:{port}  workers={workers}", _c("INFO"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except PermissionError:
        log_message("Permission denied — run as root/admin for port 53.", _c("FATAL"))
        sock.close()
        return

    with ThreadPoolExecutor(max_workers=int(workers)) as pool:
        sock.settimeout(4.0)
        while not shutdown_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                if not is_ip_allowed(addr[0]):
                    _inc("ip_reject")
                    log_message(f"IP DENIED  {addr[0]} (UDP, not in allowlist)", _c("IP_DENIED"))
                    continue
                pool.submit(_udp_handle_one, sock, data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                log_message(f"UDP loop error: {e}", _c("WARN"))
                time.sleep(0.1)

    try: sock.close()
    except Exception: pass
    log_message("UDP DNS server stopped.", _c("INFO"))

def _tcp_client_loop(client_sock, addr):
    try:
        client_sock.settimeout(TCP_CLIENT_TIMEOUT)
        while not shutdown_event.is_set():
            lp = _recv_exact(client_sock, 2)
            if not lp: break
            (msg_len,) = struct.unpack("!H", lp)
            if msg_len <= 0 or msg_len > 65535: break
            query = _recv_exact(client_sock, msg_len)
            if not query: break
            response = resolve_query(query, client_ip=addr[0])
            if not response: break
            client_sock.sendall(struct.pack("!H", len(response)) + response)
    except socket.timeout:
        pass
    except Exception as e:
        log_message(f"TCP client error {addr}: {e}", _c("WARN"))
    finally:
        try: client_sock.close()
        except Exception: pass

def start_tcp_server(host=LISTEN_HOST, port=DNS_TCP_PORT):
    log_message(f"Starting DNS (TCP) on {host}:{port}", _c("INFO"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
        srv.listen(TCP_BACKLOG)
        srv.settimeout(1.0)
    except PermissionError:
        log_message("Permission denied for TCP :53 — run as admin.", _c("FATAL"))
        srv.close(); return
    except Exception as e:
        log_message(f"TCP bind/listen failed: {e}", _c("FATAL"))
        srv.close(); return

    try:
        while not shutdown_event.is_set():
            try:
                client, addr = srv.accept()
                if not is_ip_allowed(addr[0]):
                    _inc("ip_reject")
                    log_message(f"IP DENIED  {addr[0]} (TCP, not in allowlist)", _c("IP_DENIED"))
                    try: client.close()
                    except Exception: pass
                    continue
                threading.Thread(target=_tcp_client_loop, args=(client, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                log_message(f"TCP accept error: {e}", _c("WARN"))
    finally:
        try: srv.close()
        except Exception: pass
        log_message("TCP DNS server stopped.", _c("INFO"))

# ── DNS-over-TLS Server ───────────────────────────────────────────────────────
class DoTServer(threading.Thread):
    def __init__(self, host=LISTEN_HOST, port=DOT_PORT,
                 certfile=None, keyfile=None,
                 tls_min_version=ssl.TLSVersion.TLSv1_2,
                 ciphers=None, client_timeout=30.0, backlog=200):
        super().__init__(daemon=True)
        self.host           = host
        self.port           = port
        cert_abs, key_abs   = _resolve_dot_paths()
        self.certfile       = certfile if certfile else cert_abs
        self.keyfile        = keyfile  if keyfile  else key_abs
        self.client_timeout = client_timeout
        self.backlog        = backlog
        self._shutdown      = threading.Event()
        self._sock          = None

        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = tls_min_version
        if ciphers:
            self.ctx.set_ciphers(ciphers)
        try:
            self.ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        except Exception as e:
            log_message(f"DoT certificate load failed: {e}", _c("WARN"))

    def run(self):
        base = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        base.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        base.bind((self.host, self.port))
        base.listen(self.backlog)
        base.settimeout(1.0)
        self._sock = base
        log_message(f"DNS-over-TLS listening on {self.host}:{self.port}", _c("OK"))
        try:
            while not self._shutdown.is_set() and not shutdown_event.is_set():
                try:
                    client, addr = base.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not is_ip_allowed(addr[0]):
                    _inc("ip_reject")
                    log_message(f"IP DENIED  {addr[0]} (DoT, not in allowlist)", _c("IP_DENIED"))
                    try: client.close()
                    except Exception: pass
                    continue
                threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
        finally:
            try: base.close()
            except Exception: pass

    def stop(self):
        self._shutdown.set()
        try:
            if self._sock: self._sock.close()
        except Exception: pass

    def handle_client(self, client_sock, addr):
        try:
            client_sock.settimeout(self.client_timeout)
            with self.ctx.wrap_socket(client_sock, server_side=True) as tls:
                while not shutdown_event.is_set():
                    lp = _recv_exact(tls, 2)
                    if not lp: break
                    (msg_len,) = struct.unpack("!H", lp)
                    if msg_len == 0 or msg_len > 65535: break
                    query = _recv_exact(tls, msg_len)
                    if not query: break
                    response = resolve_query(query, client_ip=addr[0])
                    if not response: break
                    tls.sendall(struct.pack("!H", len(response)) + response)
        except (ssl.SSLError, ConnectionError, socket.timeout):
            pass
        except Exception as e:
            log_message(f"DoT client error {addr}: {e}", _c("WARN"))
        finally:
            try: client_sock.close()
            except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
# SIGNAL HANDLERS  — reload / shutdown
# ══════════════════════════════════════════════════════════════════════════════
def reload_all_lists(reason: str = "signal"):
    log_message(f"Reload requested ({reason}): compact → update → load", _c("INFO"))
    try:
        compact_discovered_blocklist()
        update_blocklist_preserve()
        load_lists_into_memory()
        load_ip_allowlist()
    except Exception as e:
        log_message(f"Reload failed: {e}", _c("ERROR"))

def _handle_stop_signal(signum, frame):
    shutdown_event.set()
    log_message(f"Shutdown signal received ({signum}). Stopping…", _c("WARN"))

def _handle_reload_signal(signum, frame):
    threading.Thread(target=reload_all_lists,
                     args=(f"signal {signum}",), daemon=True).start()

if hasattr(signal, "SIGHUP"):
    signal.signal(signal.SIGHUP, _handle_reload_signal)
if hasattr(signal, "SIGBREAK"):
    signal.signal(signal.SIGBREAK, _handle_reload_signal)
for _sig in ("SIGINT", "SIGTERM"):
    if hasattr(signal, _sig):
        signal.signal(getattr(signal, _sig), _handle_stop_signal)

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(BANNER)
    log_message(f"AdVault DNS starting up — PID {os.getpid()}", _c("OK"))
    log_message(f"DoH upstreams: {', '.join(DOH_UPSTREAMS) if DOH_ENABLED else 'DISABLED'}", _c("INFO"))
    log_message(f"Plain UDP/TCP upstreams: {UPSTREAMS}", _c("INFO"))
    log_message(f"SSAI/Manifest-manipulation detection: {'ENABLED' if SSAI_DETECT_ENABLED else 'DISABLED'}", _c("SSAI"))
    log_message(f"Client IP allowlist: {'ENABLED (' + IP_ALLOWLIST_FILE + ')' if IP_ALLOWLIST_ENABLED else 'DISABLED — all clients permitted'}", _c("INFO"))

    try:
        compact_discovered_blocklist()
        log_message("Updating blocklist (no deletions)…", _c("INFO"))
        update_blocklist_preserve()
        load_lists_into_memory()

        # Load client IP allowlist — must happen before any server starts
        # accepting connections, since every server checks it at accept-time.
        load_ip_allowlist()

        # Auto-generate TLS cert/key if not already present
        auto_generate_dot_certificates()

        # DoT server
        dot = None
        try:
            dot = DoTServer()
            dot.start()
            log_message(f"DoT ENABLED on :{DOT_PORT}", _c("OK"))
        except Exception as e:
            log_message(f"DoT disabled (TLS init failed): {e}", _c("WARN"))

        # Dashboard file writer
        threading.Thread(target=write_current_users_periodically, daemon=True).start()

        # Terminal stats ticker
        if TERMINAL_STATS_ENABLED:
            threading.Thread(target=_terminal_stats_loop, daemon=True).start()
            log_message(f"Terminal stats ticker enabled (every {TERMINAL_STATS_INTERVAL}s)", _c("INFO"))

        # Plain TCP :53
        threading.Thread(target=start_tcp_server, daemon=True).start()

        log_message("All services started. Listening for DNS queries…", _c("OK"))

        # UDP :53 — blocks main thread
        start_udp_server()

    except KeyboardInterrupt:
        shutdown_event.set()
        log_message("Keyboard interrupt — shutting down.", _c("WARN"))
    except Exception as e:
        shutdown_event.set()
        log_message(f"FATAL ERROR: {e}", _c("FATAL"))
