# =============================================================
# AdVault DNS — Local Unified Resolver + DoT (Self-Signed TLS)
# Created by: Brian Cambron (https://github.com/BadInfluence69/AdVault-DNS-)
# Edition: “Local Autonomous Mode” — applies blocking to host + LAN
# =============================================================

import os, sys, io, re, time, socket, ssl, struct, threading, datetime, tempfile, signal, json, subprocess
import requests
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE
from colorama import Fore, Style, init
init(autoreset=True)

# =============================================================
# SETTINGS
# =============================================================
DOT_CERTFILE = "fullchain.pem"
DOT_KEYFILE  = "privkey.pem"
DOT_PORT     = 853
DOT_HOSTNAME = os.environ.get("ADV_DNS_HOSTNAME", "localhost")

# Redundant upstreams (DNS providers)
UPSTREAMS = [
    ("8.8.8.8", 53),       # Google DNS
    ("1.1.1.1", 53),       # Cloudflare
    ("9.9.9.9", 53),       # Quad9
    ("208.67.222.222", 53) # OpenDNS
]
UPSTREAM_TCP_TIMEOUT = 4
UPSTREAM_UDP_TIMEOUT = 4

# Sinkhole IPs
SINK_IPv4 = "0.0.0.0"
SINK_IPv6 = "::"

CACHE_MAX_ENTRIES = 50000000
CACHE_TTL_CAP = 50000000

# Files
blocklist_file = "dynamic_blocklist.txt"
allowlist_file = "allowlist.txt"
discovered_file = "discovered_blocklist.txt"
ad_insights_log = "ad_insights.txt"
catalog_file = "candidates_catalog.json"
USERS_FILE = "current_users.txt"

USERS_WRITE_INTERVAL = 3
USERS_ACTIVE_WINDOW = 3

blocklist_urls = []  # optionally add remote lists later

# =============================================================
# CORE WHITELIST (non-blockable)
# =============================================================
allowlist_critical = {
    "youtube.com","ytimg.com","pirateproxy-bay.com","i.ytimg.com","s.ytimg.com",
    "lh3.googleusercontent.com","yt3.ggpht.com","youtubei.googleapis.com","chart.js","AdVault",
    "tv.youtube.com","ytp-player-content","ytp-iv-player-content",
    "allow-storage-access-by-user-activation","allow-scripts","accounts.google.com"
}

# =============================================================
# AD KEYWORDS
# =============================================================
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
    "banner","Banner","Ad","Ads","advertisement","trafficjunky.com",
    "media.trafficjunky.net","ads.trafficjunky.com","track.trafficjunky.com",
    "cdn.trafficjunky.com","adtng.com","trafficfactory","ads.trafficfactory",
    "track.trafficfactory","cdn.trafficfactory","pb_iframe","creatives"
]))

# =============================================================
# GLOBALS
# =============================================================
discover_lock = threading.Lock()
lists_lock = threading.Lock()
catalog_lock = threading.Lock()
cache_lock = threading.Lock()
_active_lock = threading.Lock()

blocklist = set()
allowlist = set()
dns_cache = {}
_active_clients = {}
_up_idx = 0

# =============================================================
# UTILS
# =============================================================
def log_message(msg, color=Fore.WHITE):
    ts = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{color}{ts} {msg}{Style.RESET_ALL}")

def _normalize_domain(domain):
    d = domain.strip().strip(".").lower()
    try:
        d = d.encode("idna").decode("ascii")
    except Exception:
        pass
    return d

def is_valid_domain(domain):
    domain = _normalize_domain(domain)
    return bool(re.match(r"^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$", domain))

def domain_in_set_or_parent(domain, s):
    d = _normalize_domain(domain)
    if d in s:
        return True
    parts = d.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in s:
            return True
    return False

def atomic_write(path, data):
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path) or ".")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)
    os.replace(tmp, path)

def atomic_write_lines(path, items):
    atomic_write(path, "".join(sorted(d + "\n" for d in items)))

# =============================================================
# FILE HANDLERS
# =============================================================
def load_file_domains(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return {_normalize_domain(line) for line in f if is_valid_domain(line)}
    except FileNotFoundError:
        return set()

def save_domains(file_path, domains):
    try:
        atomic_write_lines(file_path, domains)
    except Exception as e:
        log_message(f"Error saving {file_path}: {e}", Fore.RED)

# =============================================================
# NETWORK & BLOCKLIST
# =============================================================
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

def _next_upstream():
    global _up_idx
    up = UPSTREAMS[_up_idx % len(UPSTREAMS)]
    _up_idx += 1
    return up

def _udp_query(qbytes):
    up = _next_upstream()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(UPSTREAM_UDP_TIMEOUT)
        s.sendto(qbytes, up)
        resp, _ = s.recvfrom(65535)
        return resp

def _tcp_query(qbytes):
    up = _next_upstream()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(UPSTREAM_TCP_TIMEOUT)
        s.connect(up)
        s.sendall(struct.pack("!H", len(qbytes)) + qbytes)
        lp = s.recv(2)
        if not lp:
            return None
        (msg_len,) = struct.unpack("!H", lp)
        return s.recv(msg_len)

# =============================================================
# CACHE
# =============================================================
def cache_get(qname, qtype):
    with cache_lock:
        v = dns_cache.get((qname, qtype))
        if not v:
            return None
        exp, blob = v
        if exp < time.time():
            dns_cache.pop((qname, qtype), None)
            return None
        return blob

def cache_put(qname, qtype, reply):
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

# =============================================================
# RESOLVER
# =============================================================
def resolve_query(qbytes):
    try:
        req = DNSRecord.parse(qbytes)
        qname = _normalize_domain(str(req.q.qname))
        qtype = req.q.qtype

        log_message(f"Query: {qname}", Fore.WHITE)

        if is_blocked(qname):
            log_message(f"BLOCKED: {qname}", Fore.RED)
            reply = req.reply()
            if qtype in (QTYPE.A, QTYPE.ANY):
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(SINK_IPv4), ttl=60))
            if qtype in (QTYPE.AAAA, QTYPE.ANY):
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(SINK_IPv6), ttl=60))
            return reply.pack()

        cached = cache_get(qname, qtype)
        if cached:
            log_message(f"CACHE HIT: {qname}", Fore.CYAN)
            return cached

        for _ in range(len(UPSTREAMS)):
            try:
                resp = _udp_query(qbytes)
                parsed = DNSRecord.parse(resp)
                if parsed.header.tc == 1:
                    raise ValueError("Truncated")
                break
            except Exception:
                resp = _tcp_query(qbytes)
                if resp:
                    break
        else:
            log_message(f"All upstreams failed for {qname}", Fore.RED)
            raise Exception("No upstreams")

        parsed = DNSRecord.parse(resp)
        cache_put(qname, qtype, parsed)
        log_message(f"RESOLVED: {qname}", Fore.GREEN)
        return resp

    except Exception as e:
        log_message(f"Resolver error: {e}", Fore.RED)
        try:
            req = DNSRecord.parse(qbytes)
            servfail = req.reply()
            servfail.header.rcode = RCODE.SERVFAIL
            return servfail.pack()
        except Exception:
            return b""

# =============================================================
# UDP SERVER
# =============================================================
def handle_request(data, addr, sock):
    try:
        resp = resolve_query(data)
        if resp:
            sock.sendto(resp, addr)
            mark_active(addr)
    except Exception as e:
        log_message(f"Error handling {addr}: {e}", Fore.RED)

def start_udp_server(host="0.0.0.0", port=53):
    log_message(f"Starting UDP DNS on {host}:{port}", Fore.CYAN)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((host, port))
        except PermissionError:
            log_message("Permission denied! Run as Admin.", Fore.RED)
            return
        while True:
            data, addr = sock.recvfrom(65535)
            threading.Thread(target=handle_request, args=(data, addr, sock), daemon=True).start()

# =============================================================
# DoT SERVER
# =============================================================
class DoTServer(threading.Thread):
    def __init__(self, host="0.0.0.0", port=DOT_PORT):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            self.ctx.load_cert_chain(certfile=DOT_CERTFILE, keyfile=DOT_KEYFILE)
        except Exception as e:
            log_message(f"TLS init failed: {e}", Fore.YELLOW)

    def run(self):
        base = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        base.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        base.bind((self.host, self.port))
        base.listen(200)
        log_message(f"DNS-over-TLS running on {self.host}:{self.port}", Fore.GREEN)
        while True:
            client, addr = base.accept()
            threading.Thread(target=self.handle, args=(client, addr), daemon=True).start()

    def handle(self, client, addr):
        try:
            with self.ctx.wrap_socket(client, server_side=True) as tls:
                while True:
                    lp = tls.recv(2)
                    if not lp:
                        break
                    (msg_len,) = struct.unpack("!H", lp)
                    query = tls.recv(msg_len)
                    resp = resolve_query(query)
                    if not resp:
                        break
                    tls.sendall(struct.pack("!H", len(resp)) + resp)
        except Exception:
            pass
        finally:
            client.close()

# =============================================================
# ACTIVE USER TRACKING
# =============================================================
def mark_active(addr):
    ip = addr[0]
    now = time.time()
    with _active_lock:
        _active_clients[ip] = now

def write_current_users_periodically():
    while True:
        now = time.time()
        cutoff = now - USERS_ACTIVE_WINDOW
        with _active_lock:
            for ip in list(_active_clients.keys()):
                if _active_clients[ip] < cutoff:
                    _active_clients.pop(ip, None)
            atomic_write(USERS_FILE, str(len(_active_clients)))
        time.sleep(USERS_WRITE_INTERVAL)

# =============================================================
# STARTUP
# =============================================================
if __name__ == "__main__":
    log_message("Initializing AdVault DNS...", Fore.CYAN)

    # Ensure certs exist
    if not (os.path.exists(DOT_CERTFILE) and os.path.exists(DOT_KEYFILE)):
        log_message("Generating self-signed TLS certificate...", Fore.CYAN)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", DOT_KEYFILE, "-out", DOT_CERTFILE,
            "-days", "365", "-nodes", "-subj", f"/CN={DOT_HOSTNAME}"
        ], check=False)

    # Load lists
    blocklist = load_file_domains(blocklist_file)
    allowlist = load_file_domains(allowlist_file)
    log_message(f"Loaded blocklist: {len(blocklist)} domains", Fore.CYAN)
    log_message(f"Loaded allowlist: {len(allowlist)} domains", Fore.CYAN)

    # Start services
    threading.Thread(target=write_current_users_periodically, daemon=True).start()
    try:
        dot = DoTServer()
        dot.start()
    except Exception as e:
        log_message(f"DoT disabled: {e}", Fore.YELLOW)

    start_udp_server()
