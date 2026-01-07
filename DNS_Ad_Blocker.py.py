# AdVault DNS — Unified Single-File Resolver (+ DNS-over-TLS with auto cert)
# created by: "Brian Cambron" | Github: https://github.com/BadInfluence69/AdVault-DNS-
# revised: 03/16/2002

import os, sys, io, re, time, socket, ssl, struct, threading, datetime, tempfile, signal, json
import ipaddress, math
from collections import Counter

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import requests
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE, CNAME
from colorama import Fore, Style, init
init(autoreset=True)

# ============================
# SETTINGS
# ============================
DOT_CERTFILE = "fullchain.pem"
DOT_KEYFILE  = "privkey.pem"
DOT_PORT     = 853
UPSTREAMS    = [("8.8.8.8", 53)]
UPSTREAM_TCP_TIMEOUT = 4
UPSTREAM_UDP_TIMEOUT = 4
SINK_IPv4    = "0.0.0.0"
SINK_IPv6    = "::"
DOT_HOSTNAME = os.environ.get("ADV_DNS_HOSTNAME", "localhost")

CACHE_MAX_ENTRIES = 500000000
CACHE_TTL_CAP = 3600

blocklist_file   = "dynamic_blocklist.txt"
allowlist_file   = "allowlist.txt"
discovered_file  = "discovered_blocklist.txt"
ad_insights_log  = "ad_insights.txt"
catalog_file     = "candidates_catalog.json"
USERS_FILE           = "current_users.txt"
USERS_WRITE_INTERVAL = 3
USERS_ACTIVE_WINDOW  = 3

blocklist_urls = [
    "http://127.0.0.1/Advault/dynamic_blocklist.txt",
    "http://127.0.0.1/Advault/discovered_blocklist.txt",
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    "https://filters.adtidy.org/extension/chromium/filters/2.txt",
    "https://filters.adtidy.org/extension/chromium/filters/3.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://big.oisd.nl/",
    "https://badmojr.github.io/1Hosts/Lite/domains.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

allowlist_critical = {
    "youtube.com","ytimg.com","pirateproxy-bay.com","i.ytimg.com","s.ytimg.com",
    "lh3.googleusercontent.com","yt3.ggpht.com","youtubei.googleapis.com","chart.js","AdVault",
    "tv.youtube.com","ytp-player-content","ytp-iv-player-content",
    "allow-storage-access-by-user-activation","allow-scripts","accounts.google.com"
}

AD_HOST_KEYWORDS = [
     "ad.", ".ad.", "ads.", ".ads.", "adservice", "adserver", "advert", "doubleclick",
    "googlesyndication", "googletagservices", "googletagmanager", "adnxs", "moatads",
    "taboola", "outbrain", "criteo", "rubiconproject", "serving-sys", "zemanta",
    "pubmatic", "yieldmo", "omtrdc", "scorecardresearch", "zedo", "revcontent",
    "adform", "openx", "quantserve", "quantcount", "demdex", "rfihub", "everesttech",
    "adsrvr", "casalemedia", "exoclick", "propellerads", "popads", "mgid", "teads",
    "smartadserver", "adcolony", "chartboost", "fyber", "inmobi", "unityads", "applovin",
    "ironsrc", "tracking", "tracker", "pixel", "beacon", "affiliate", "clk.", "click."
]

keyword_blocklist = list(set([
    "SCTE-35", "banner", "Banner", "Ad", "Ads", "advertisement", "trafficjunky.com",
    "media.trafficjunky.net","ads.trafficjunky.com", "track.trafficjunky.com",
    "cdn.trafficjunky.com", "adtng.com", "trafficfactory", "ads.trafficfactory",
    "track.trafficfactory", "cdn.trafficfactory", "pb_iframe", "creatives",
    "metrics",
    "analytics",
    "telemetry",
    "insight",
    "experiment",
    "abtest",
    "optimize",
    "personalize",
    "audience",
    "segment",
    "segmentio",
    "snowplow",
    "amplitude",
    "mixpanel",
    "newrelic",
    "datadog",
    "app-measurement",
    "firebase",
    "measurement",
    "stats",
    "collect",
    "collector",
    "events",
    "logging",
    "monitor",
]))

# Ad Detection

DETECT_AD_MARKERS            = True
DETECT_AD_INJECTION          = True
AUTO_BLOCK_INJECTED_CNAME    = True   # If an allowed name CNAMEs into an ad/tracker, sink it
LOG_AD_INSIGHTS              = True

# Extra marker keywords (in addition to AD_HOST_KEYWORDS / keyword_blocklist)
AD_MARKER_KEYWORDS = [
    "scte-35", "scte35",
    "admarker", "ad-mark", "ad_mark",
    "adbreak", "ad-break", "ad_break",
    "preroll", "midroll", "postroll",
    "vast", "vpaid", "ima", "adtag", "ad-tag", "ad_tag",
    "doubleclick", "googlesyndication", "googletagmanager", "googletagservices",
    "tracking", "tracker", "telemetry", "marker", "analytics", "pixel", "beacon",
]

# NXDOMAIN / wildcard hijack-ish detection (best-effort heuristic)
INJECTION_WILDCARD_WINDOW   = 300   # 5 minutes
INJECTION_WILDCARD_THRESHOLD = 25   # distinct random-ish names pointing to same IP in window
INJECTION_WILDCARD_TTL_MAX   = 120  # low TTL is common in hijack/wildcard setups
_injection_lock = threading.Lock()
_injection_ip_stats = {}  # ip -> {"first":ts,"last":ts,"names":set([...])}

# ============================
# GLOBAL STATE
# ============================
discover_lock = threading.Lock()
lists_lock = threading.Lock()
catalog_lock = threading.Lock()
cache_lock = threading.Lock()

blocklist = set()
allowlist = set()
_up_idx = 0
dns_cache = dict()
_active_clients = {}
_active_lock = threading.Lock()

_insights_lock = threading.Lock()

# ============================
# HELPERS
# ============================
def log_message(message, color=Fore.WHITE):
    ts = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{color}{ts} {message}{Style.RESET_ALL}")

def _normalize_domain(domain: str) -> str:
    d = domain.strip().strip(".").lower()
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
    atomic_write(path, "".join(sorted(d+"\n" for d in items)))

def append_line(path: str, line: str):
    # Thread-safe append for insights (minimal overhead)
    try:
        with _insights_lock:
            with open(path, "a", encoding="utf-8", errors="replace") as f:
                f.write(line.rstrip("\n") + "\n")
    except Exception:
        pass

def _now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_ad_insight(kind: str, client_ip: str, qname: str, detail: str = ""):
    if not LOG_AD_INSIGHTS:
        return
    line = f"[{_now_ts()}] {kind} | client={client_ip or 'unknown'} | host={qname} | {detail}".rstrip()
    append_line(ad_insights_log, line)

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    ent = 0.0
    for k, v in c.items():
        p = v / n
        ent -= p * math.log2(p)
    return ent

def looks_like_random_subdomain(domain: str) -> bool:
    """
    Very light heuristic: flags some DGA-ish / tracking-ish random labels.
    This is NOT a block rule by itself—only a signal for logging/injection heuristics.
    """
    d = _normalize_domain(domain)
    parts = d.split(".")
    if len(parts) < 3:
        return False

    left = parts[0]
    if len(left) < 14:
        return False

    # High entropy label with many digits tends to be tracking / cache-bust
    ent = _shannon_entropy(left)
    digit_ratio = sum(ch.isdigit() for ch in left) / max(1, len(left))
    vowel_ratio = sum(ch in "aeiou" for ch in left) / max(1, len(left))

    if ent >= 3.2 and digit_ratio >= 0.20:
        return True
    if ent >= 3.5 and vowel_ratio <= 0.20:
        return True
    return False

def is_private_or_special_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return bool(
            ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or
            ip.is_link_local or ip.is_unspecified
        )
    except Exception:
        return False

def _collect_cname_targets(dnsrec: DNSRecord) -> list:
    targets = []
    try:
        # Check answers, authority, additional
        for rr in list(getattr(dnsrec, "rr", [])) + list(getattr(dnsrec, "auth", [])) + list(getattr(dnsrec, "ar", [])):
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

def _track_possible_wildcard_injection(qname: str, ips_with_ttl: list, client_ip: str):
    """
    Best-effort heuristic for wildcard/NXDOMAIN-hijack-like behavior:
    many random-ish hostnames mapping to the same IP within a short window.
    (With Google upstream this is unlikely, but the logic is here as requested.)
    """
    if not ips_with_ttl:
        return

    d = _normalize_domain(qname)
    if not looks_like_random_subdomain(d):
        return

    # Use first IP as primary signal
    ip, ttl = ips_with_ttl[0]
    if ttl is None:
        ttl = 0

    # Low TTL is a common indicator (not definitive)
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

        # Prune old
        cutoff = now - INJECTION_WILDCARD_WINDOW
        for k in list(_injection_ip_stats.keys()):
            if _injection_ip_stats[k]["last"] < cutoff:
                _injection_ip_stats.pop(k, None)

        # Trigger if too many distinct random-ish names to same IP
        if len(st["names"]) >= INJECTION_WILDCARD_THRESHOLD:
            detail = f"suspected_wildcard_or_hijack ip={ip} distinct_randomish={len(st['names'])} ttl<= {INJECTION_WILDCARD_TTL_MAX}"
            log_message(f"AD INJECTION SUSPECT (wildcard/hijack): {detail}", color=Fore.MAGENTA)
            log_ad_insight("INJECTION_WILDCARD", client_ip, d, detail)

def detect_ad_markers(client_ip: str, qname: str, qtype: int):
    if not DETECT_AD_MARKERS:
        return

    d = _normalize_domain(qname)
    qtype_name = QTYPE.get(qtype, str(qtype))

    # Marker keyword hits (lowercased)
    marker_hits = []
    for kw in AD_MARKER_KEYWORDS:
        k = kw.lower()
        if k and k in d:
            marker_hits.append(k)

    # Host keyword hits (already tuned for ad-ish hosts)
    host_hits = []
    for kw in AD_HOST_KEYWORDS:
        k = kw.lower()
        if k and k in d:
            host_hits.append(k)

    # DGA-ish / cache-bust-ish (signal only)
    randomish = looks_like_random_subdomain(d)

    if marker_hits:
        detail = f"markers={','.join(sorted(set(marker_hits)))} qtype={qtype_name}"
        log_message(f"AD MARKER SIGNAL: {d} ({detail})", color=Fore.MAGENTA)
        log_ad_insight("AD_MARKER", client_ip, d, detail)

    if host_hits:
        detail = f"host_keywords={','.join(sorted(set(host_hits)))} qtype={qtype_name}"
        log_message(f"AD HOST SIGNAL: {d} ({detail})", color=Fore.MAGENTA)
        log_ad_insight("AD_HOST_SIGNAL", client_ip, d, detail)

    if randomish:
        detail = f"randomish_subdomain qtype={qtype_name}"
        log_ad_insight("RANDOMISH_HOST", client_ip, d, detail)

def detect_and_mitigate_ad_injection(request: DNSRecord, parsed_reply: DNSRecord, client_ip: str):
    """
    Detect:
      - CNAME chains pointing into blocked/candidate ad hosts
      - suspicious wildcard/hijack patterns (log only)
      - private/special IP answers (log only)
    Mitigate (optional):
      - If allowed qname CNAMEs into a blocked/candidate: sink it (AUTO_BLOCK_INJECTED_CNAME)
    """
    if not DETECT_AD_INJECTION:
        return None

    qname = _normalize_domain(str(request.q.qname))
    qtype = request.q.qtype

    # 1) CNAME injection-ish: allowed host resolves via ad/tracker CNAME
    cname_targets = _collect_cname_targets(parsed_reply)
    for t in cname_targets:
        # Ignore if critical allowlisted (avoid breaking important service chains)
        if domain_in_set_or_parent(t, allowlist_critical) or domain_in_set_or_parent(t, allowlist):
            continue

        is_target_blocked = is_blocked(t)
        is_target_candidate = hostname_is_ad_candidate(t)

        if is_target_blocked or is_target_candidate:
            kind = "INJECTION_CNAME_BLOCKED" if is_target_blocked else "INJECTION_CNAME_CANDIDATE"
            detail = f"cname_target={t} qtype={QTYPE.get(qtype, str(qtype))}"

            log_message(f"AD INJECTION SIGNAL: {qname} -> CNAME {t}", color=Fore.MAGENTA)
            log_ad_insight(kind, client_ip, qname, detail)

            # Keep your existing discovery/catalog logic, but add the CNAME target too
            if is_target_candidate and not is_target_blocked:
                try:
                    catalog_candidate(t)
                except Exception:
                    pass
                try:
                    add_discovered_domain(t)
                except Exception:
                    pass

            if AUTO_BLOCK_INJECTED_CNAME:
                # Sink the response for A/AAAA/ANY queries (others get an empty NOERROR reply)
                reply = request.reply()
                reply.header.rcode = RCODE.NOERROR
                if qtype in (QTYPE.A, QTYPE.ANY):
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(SINK_IPv4), ttl=60))
                if qtype in (QTYPE.AAAA, QTYPE.ANY):
                    reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(SINK_IPv6), ttl=60))

                log_message(f"INJECTION MITIGATED (sunk): {qname} (via {t})", color=Fore.RED)
                log_ad_insight("INJECTION_SUNK", client_ip, qname, f"via_cname={t}")
                return reply.pack()

            # If not auto-blocking, we still just log and continue
            break

    # 2) Wildcard/hijack-ish patterns (log only)
    ips_with_ttl = _collect_a_aaaa_answers(parsed_reply)
    _track_possible_wildcard_injection(qname, ips_with_ttl, client_ip)

    # 3) Private/special IP answers (log only; sometimes captive portal / injection)
    for ip, ttl in ips_with_ttl[:4]:
        if is_private_or_special_ip(ip):
            detail = f"special_ip_answer ip={ip} ttl={ttl}"
            log_ad_insight("SPECIAL_IP_ANSWER", client_ip, qname, detail)

    return None

# ============================
# FILE IO
# ============================
def load_file_domains(file_path: str) -> set:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return {_normalize_domain(line) for line in f if is_valid_domain(line)}
    except FileNotFoundError:
        return set()

def save_domains(file_path: str, domains: set):
    try:
        atomic_write_lines(file_path, domains)
    except Exception as e:
        log_message(f"Error saving {file_path}: {e}", color=Fore.RED)

def load_catalog() -> dict:
    try:
        with open(catalog_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_catalog(cat: dict):
    try:
        atomic_write(catalog_file, json.dumps(cat, ensure_ascii=False, indent=2))
    except Exception as e:
        log_message(f"Error saving {catalog_file}: {e}", color=Fore.RED)

# ============================
# HTTP USER-AGENT SPOOF
# ============================
http = requests.Session()
http.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36",
    "Accept": "*/*", "Connection": "close",
})

def fetch_blocklist(url):
    try:
        r = http.get(url, timeout=10)
        r.raise_for_status()
        return r.text
    except requests.exceptions.RequestException as e:
        log_message(f"Failed to fetch blocklist from {url}: {e}", color=Fore.YELLOW)
        return ""

def parse_blocklist(raw_data):
    domains = set()
    for line in raw_data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if "||" in line:
            domain = line.split("||",1)[1].split("^",1)[0]
        elif "$" in line:
            m = re.search(r"domain=([a-zA-Z0-9.-]+)", line)
            domain = m.group(1) if m else ""
        else:
            domain = line
        domain = _normalize_domain(domain)
        if is_valid_domain(domain):
            domains.add(domain)
    return domains

# ============================
# BLOCK/ALLOW LIST MGMT
# ============================
def compact_discovered_blocklist():
    discovered = load_file_domains(discovered_file)
    if discovered:
        save_domains(discovered_file, discovered)
        log_message(f"Compacted discovered list to {len(discovered)} domains.", color=Fore.CYAN)

def update_blocklist_preserve():
    with lists_lock:
        existing = load_file_domains(blocklist_file)
        collected = set(existing)
        for url in blocklist_urls:
            log_message(f"Fetching blocklist from {url}...", color=Fore.CYAN)
            raw = fetch_blocklist(url)
            if raw:
                ds = parse_blocklist(raw)
                log_message(f"Extracted {len(ds)} valid domains from {url}.", color=Fore.CYAN)
                collected.update(ds)
        local_discovered = load_file_domains(discovered_file)
        if local_discovered:
            log_message(f"Including {len(local_discovered)} locally discovered ad domains.", color=Fore.CYAN)
            collected.update(local_discovered)
        save_domains(blocklist_file, collected)
        log_message(f"Blocklist updated with {len(collected)} domains (no deletions).", color=Fore.GREEN)

def load_lists_into_memory():
    global blocklist, allowlist
    with lists_lock:
        blocklist = load_file_domains(blocklist_file)
        allowlist = load_file_domains(allowlist_file)
    log_message(f"In-memory lists: block={len(blocklist)} allow={len(allowlist)}", color=Fore.CYAN)

# ============================
# DISCOVERY
# ============================
def hostname_is_ad_candidate(domain: str) -> bool:
    d = _normalize_domain(domain)
    return any(k in d for k in AD_HOST_KEYWORDS)

def catalog_candidate(domain: str):
    d = _normalize_domain(domain)
    if not is_valid_domain(d): return
    if domain_in_set_or_parent(d, allowlist_critical) or domain_in_set_or_parent(d, allowlist):
        return
    if d in blocklist: return
    with catalog_lock:
        cat = load_catalog()
        now = int(time.time())
        if d not in cat:
            cat[d] = {"count": 1, "first": now, "last": now}
        else:
            cat[d]["count"] += 1
            cat[d]["last"] = now
        save_catalog(cat)

def add_discovered_domain(domain: str):
    d = _normalize_domain(domain)
    if not is_valid_domain(d): return
    if domain_in_set_or_parent(d, allowlist_critical) or domain_in_set_or_parent(d, allowlist):
        return
    if d in blocklist: return
    with discover_lock:
        current = load_file_domains(discovered_file)
        if d in current: return
        current.add(d)
        save_domains(discovered_file, current)
        log_message(f"Discovered ad domain added: {d}", color=Fore.MAGENTA)

def is_blocked(domain):
    d = _normalize_domain(domain)
    if domain_in_set_or_parent(d, allowlist_critical) or domain_in_set_or_parent(d, allowlist):
        return False
    if d in blocklist:
        return True
    for kw in keyword_blocklist:
        if kw in d:
            return True
    return False

# ============================
# CACHE
# ============================
def cache_get(qname: str, qtype: int):
    k = (qname, qtype)
    with cache_lock:
        v = dns_cache.get(k)
        if not v: return None
        exp, blob = v
        if exp < time.time():
            dns_cache.pop(k, None)
            return None
        return blob

def cache_put(qname: str, qtype: int, reply: DNSRecord):
    try:
        ttls = [rr.ttl for rr in reply.rr if str(rr.rname).strip(".").lower() == qname]
        ttl = max(5, min(CACHE_TTL_CAP, min(ttls) if ttls else 30))
        exp = time.time() + ttl
        blob = reply.pack()
        with cache_lock:
            if len(dns_cache) > CACHE_MAX_ENTRIES:
                dns_cache.clear()
            dns_cache[(qname, reply.q.qtype)] = (exp, blob)
    except Exception:
        pass

# ============================
# CORE RESOLUTION
# ============================
def _next_upstream():
    global _up_idx
    up = UPSTREAMS[_up_idx % len(UPSTREAMS)]
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

def _udp_query(query_bytes: bytes):
    up = _next_upstream()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(UPSTREAM_UDP_TIMEOUT)
            s.sendto(query_bytes, up)
            resp, _ = s.recvfrom(65535)
            return resp
    except Exception as e:
        log_message(f"UDP failed on {up}: {e}", color=Fore.YELLOW)
        raise

def _tcp_query(query_bytes: bytes):
    up = _next_upstream()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(UPSTREAM_TCP_TIMEOUT)
            s.connect(up)
            s.sendall(struct.pack("!H", len(query_bytes)) + query_bytes)
            lp = _recv_exact(s, 2)
            if not lp:
                return None
            (msg_len,) = struct.unpack("!H", lp)
            return _recv_exact(s, msg_len)
    except Exception as e:
        log_message(f"TCP failed on {up}: {e}", color=Fore.YELLOW)
        raise

def resolve_query(query_bytes: bytes, client_ip: str = None) -> bytes:
    try:
        request = DNSRecord.parse(query_bytes)
        qname = _normalize_domain(str(request.q.qname))
        qtype = request.q.qtype

        log_message(f"Query received: {qname}", color=Fore.WHITE)

        # --- AD MARKER / SIGNAL DETECTION (log-only) ---
        detect_ad_markers(client_ip or "unknown", qname, qtype)

        if hostname_is_ad_candidate(qname):
            catalog_candidate(qname)

        if is_blocked(qname):
            log_message(f"BLOCKED: {qname}", color=Fore.RED)
            log_ad_insight("BLOCKED", client_ip or "unknown", qname, f"qtype={QTYPE.get(qtype, str(qtype))}")
            reply = request.reply()
            if qtype in (QTYPE.A, QTYPE.ANY):
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(SINK_IPv4), ttl=60))
            if qtype in (QTYPE.AAAA, QTYPE.ANY):
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(SINK_IPv6), ttl=60))
            return reply.pack()
        else:
            log_message(f"ALLOWED: {qname}", color=Fore.GREEN)

        cached = cache_get(qname, qtype)
        if cached:
            log_message(f"CACHE HIT: {qname}", color=Fore.CYAN)
            return cached

        errors = []
        for _ in range(len(UPSTREAMS)):
            try:
                resp = _udp_query(query_bytes)
                parsed = DNSRecord.parse(resp)
                if parsed.header.tc == 1:
                    raise ValueError("TC bit set")
                break
            except Exception as e_udp:
                errors.append(f"UDP: {e_udp}")
                try:
                    resp = _tcp_query(query_bytes)
                    if resp:
                        break
                except Exception as e_tcp:
                    errors.append(f"TCP: {e_tcp}")
        else:
            log_message(f"All upstreams failed for {qname}: {errors}", color=Fore.RED)
            raise Exception("All upstreams failed")

        parsed = DNSRecord.parse(resp)

        # --- AD INJECTION / MARKER DETECTION (and optional mitigation) ---
        override = detect_and_mitigate_ad_injection(request, parsed, client_ip or "unknown")
        if override:
            return override

        if hostname_is_ad_candidate(qname) and not is_blocked(qname):
            add_discovered_domain(qname)

        cache_put(qname, qtype, parsed)

        log_message(f"RESOLVED: {qname}", color=Fore.BLUE)
        return resp

    except Exception as e:
        log_message(f"Resolver error: {e}", color=Fore.RED)
        try:
            req = DNSRecord.parse(query_bytes)
            servfail = req.reply()
            servfail.header.rcode = RCODE.SERVFAIL
            return servfail.pack()
        except Exception:
            return b""

# ============================
# ACTIVE USER TRACKING
# ============================
def mark_active(addr):
    ip = addr[0]
    now = time.time()
    with _active_lock:
        _active_clients[ip] = now

def _prune_and_count(now=None):
    if now is None: now = time.time()
    cutoff = now - USERS_ACTIVE_WINDOW
    with _active_lock:
        stale = [ip for ip, ts in _active_clients.items() if ts < cutoff]
        for ip in stale:
            _active_clients.pop(ip, None)
        return len(_active_clients)

def write_current_users_periodically():
    while True:
        try:
            count = _prune_and_count()
            atomic_write(USERS_FILE, str(count))
        except Exception as e:
            log_message(f"User count write fail: {e}", Fore.YELLOW)
        time.sleep(USERS_WRITE_INTERVAL)

# ============================
# UDP SERVER
# ============================
def handle_request(data, addr, sock):
    try:
        response = resolve_query(data, client_ip=addr[0])
        if response:
            sock.sendto(response, addr)
            mark_active(addr)
    except Exception as e:
        log_message(f"Error handling request: {e}", color=Fore.RED)

def start_udp_server(host="0.0.0.0", port=53):
    log_message(f"Starting DNS (UDP) on {host}:{port}", color=Fore.CYAN)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((host, port))
        except PermissionError:
            log_message("Permission denied! Use port > 1024 or run as admin.", color=Fore.RED)
            return
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                handle_request(data, addr, sock)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log_message(f"Non-fatal loop error: {e}", color=Fore.YELLOW)
                time.sleep(0.2)
    log_message("Shutting down UDP...DNS.", color=Fore.CYAN)

# ============================
# DoT SERVER
# ============================
class DoTServer(threading.Thread):
    def __init__(self, host="0.0.0.0", port=DOT_PORT, certfile=DOT_CERTFILE, keyfile=DOT_KEYFILE,
                 tls_min_version=ssl.TLSVersion.TLSv1_2, ciphers=None, client_timeout=30.0, backlog=200):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.client_timeout = client_timeout
        self.backlog = backlog
        self._shutdown = threading.Event()
        self._sock = None
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = tls_min_version
        if ciphers:
            self.ctx.set_ciphers(ciphers)
        try:
            self.ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        except Exception as e:
            log_message(f"Certificate load failed: {e}", color=Fore.YELLOW)

    def run(self):
        base = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        base.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        base.bind((self.host, self.port))
        base.listen(self.backlog)
        self._sock = base
        log_message(f"Starting DNS-over-TLS (TCP) on {self.host}:{self.port}", color=Fore.CYAN)
        try:
            while not self._shutdown.is_set():
                try:
                    client, addr = base.accept()
                except OSError:
                    break
                threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
        finally:
            try:
                base.close()
            except Exception:
                pass

    def stop(self):
        self._shutdown.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def handle_client(self, client_sock, addr):
        try:
            client_sock.settimeout(self.client_timeout)
            with self.ctx.wrap_socket(client_sock, server_side=True) as tls:
                while True:
                    lp = _recv_exact(tls, 2)
                    if not lp:
                        break
                    (msg_len,) = struct.unpack("!H", lp)
                    if msg_len == 0 or msg_len > 65535:
                        break
                    query = _recv_exact(tls, msg_len)
                    if not query:
                        break
                    response = resolve_query(query, client_ip=addr[0])
                    if not response:
                        break
                    tls.sendall(struct.pack("!H", len(response)) + response)
                    # Track DoT clients in your active user logic too
                    mark_active(addr)
        except (ssl.SSLError, ConnectionError, socket.timeout):
            pass
        except Exception as e:
            log_message(f"DoT client error {addr}: {e}", color=Fore.YELLOW)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

# ============================
# SIGNAL HANDLERS (reload)
# ============================
def handle_sighup(signum, frame):
    log_message("SIGHUP received: reloading lists...", color=Fore.CYAN)
    try:
        compact_discovered_blocklist()
        update_blocklist_preserve()
        load_lists_into_memory()
    except Exception as e:
        log_message(f"Reload failed: {e}", color=Fore.RED)

if hasattr(signal, "SIGHUP"):
    signal.signal(signal.SIGHUP, handle_sighup)

# ============================
# MAIN
# ============================
if __name__ == "__main__":
    try:
        compact_discovered_blocklist()
        log_message("Updating blocklist (no deletions)...", color=Fore.CYAN)
        update_blocklist_preserve()
        load_lists_into_memory()

        try:
            dot = DoTServer()
            dot.start()
            log_message(f"DoT ENABLED (TLS on :{DOT_PORT}).", color=Fore.GREEN)
        except Exception as e:
            log_message(f"DoT disabled (TLS init failed): {e}", color=Fore.YELLOW)

        threading.Thread(target=write_current_users_periodically, daemon=True).start()
        start_udp_server()

    except KeyboardInterrupt:
        log_message("Shutting down.", color=Fore.CYAN)
    except Exception as e:
        log_message(f"FATAL ERROR: {e}", color=Fore.RED)
