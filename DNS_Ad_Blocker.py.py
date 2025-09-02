# AdVault DNS — Unified Single-File Resolver (+ DNS-over-TLS with auto cert)
# created by: "Brian Cambron" | Github: https://github.com/BadInfluence69/AdVault-DNS-

import os
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import requests
import socket
import ssl
import struct
from dnslib import DNSRecord, QTYPE, RR, A, AAAA, RCODE
import re
import time
import threading
import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# ============================
# BASIC SETTINGS
# ============================
DOT_CERTFILE = "fullchain.pem"
DOT_KEYFILE  = "privkey.pem"
DOT_PORT     = 853
UPSTREAM_DNS = ("8.8.8.8", 53)  # upstream for allowed queries
SINK_IP      = "185.107.97.246" # your original sink for blocked A queries
DOT_HOSTNAME = os.environ.get("ADV_DNS_HOSTNAME", "localhost")  # CN/SAN for self-signed default

# ============================
# SPOOFED USER-AGENT LOGIC (server-side HTTP fetches only)
# ============================
spoofed_headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36",
    "Accept": "*/*",
    "Connection": "close",
}
http = requests.Session()
http.headers.update(spoofed_headers)

def build_raw_get(host, path="/"):
    head_lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        *[f"{k}: {v}" for k, v in spoofed_headers.items()],
        "Accept: */*",
        "Connection: close",
    ]
    return ("\r\n".join(head_lines) + "\r\n\r\n").encode("ascii", "ignore")

# ============================
# STATE / FILES
# ============================
active_users = set()
discover_lock = threading.Lock()

blocklist_file = "dynamic_blocklist.txt"
allowlist_file = "allowlist.txt"
discovered_file = "discovered_blocklist.txt"  # <— clean domains ONLY
ad_insights_log = "ad_insights.txt"           # <— human-readable matches/snippets

blocklist_urls = [
    "http://185.107.97.246/AdVault/dynamic_blocklist.txt",
    "http://185.107.97.246/AdVault/ad_insights.txt",
]

allowlist_critical = {
    "det_apb_b","ab_det_apm","ab_ab_det_el_h","ab_det_em_inj","ab_det_pp_ov",
    "ab_l_sig_st","ab_l_sig_st_e","ab_sa_ef",
    "youtube.com","ytimg.com","pirateproxy-bay.com","i.ytimg.com","s.ytimg.com",
    "lh3.googleusercontent.com","yt3.ggpht.com","youtubei.googleapis.com","chart.js","AdVault",
    "tv.youtube.com","ytp-player-content","ytp-iv-player-content",
    "allow-storage-access-by-user-activation","allow-scripts","accounts.google.com"
}

# Keyword heuristics for auto-discovery (hostnames)
AD_HOST_KEYWORDS = [
    "ad.", ".ad.", "ads.", ".ads.", "adservice", "adserver", "adservers", "advert",
    "doubleclick", "googlesyndication", "googletagservices", "googletagmanager",
    "g.doubleclick.net", "adnxs", "moatads", "taboola", "outbrain", "criteo",
    "rubiconproject", "serving-sys", "zemanta", "pubmatic", "yieldmo", "omtrdc",
    "scorecardresearch", "zedo", "revcontent", "adform", "openx", "quantserve",
    "quantcount", "demdex", "rfihub", "everesttech", "adsrvr", "casalemedia",
    "exoclick", "propellerads", "popads", "popcash", "mgid", "teads", "smartadserver",
    "adcolony", "chartboost", "fyber", "inmobi", "unityads", "applovin", "ironsrc",
    "tracking", "tracker", "track.", ".track.", "pixel", "beacon", "affiliate",
    "clk.", ".clk.", "click.", ".click."
]

# (kept primarily for your logging; DNS packets rarely carry these strings)
AD_CONTENT_PATTERNS = list(set([
    r'media?url=https%3A%2F%2Fexternal-preview.redd.it%*',
    r'iframe[src*="ad"]', r'div[id*="ad"]', r'div[class*="ad"]', r'section[class*="ad"]',
    r'div[class*="sponsor"]', r'div[class*="banner"]', r'div[id*="sponsor"]',
    r'div[class*="adsbygoogle"]', r'ins.adsbygoogle {', r'track.js', r'tracker.js',
    r'trackers.js', r'admodel', r'ad-model', r'ytp-o', r'adselector', r'ytp-', r'adsystem',
    r'orbsrv', r'afcdn', r'exo-native-widget', r'click\.php\?d=', r'loop', r'ytp-popup',
    r'blob:https://.*pornhub.com/', r'blob:https://.*youtube.com/', r'trafficfactory',
    r'aria-haspopup="true"', r'playinline', r'\.webp', r'\.php\?d=', r'xnxx\.gold', r'\.gold\?pmsc',
    r'header_adblock', r'session_token', r'-ads-', r'xplayer-ads-block__callToAction--with-title',
    r'sfw-av-popup', r'data-role="auto-generated-banner-container"', r'display.',
    r'<video[^>]*src="blob:https://www\.youtube\.com.*"></video>', r'ytp-gated-actions-overlay',
    r'_video.mp4', r'ggpht.com', r'ytp-id-22', r'blob:', r'aria-haspopup', r'uploaded_content',
    r'allow-popups', r"xplayer-abs-block__link", r'prefetch', r'preconnect',
    r'ytp-free-preview-countdown-timer', r"ytd-offer-content-renderer",
    r'premium-log-overlay', r'ad.', r'popup.',
]))

keyword_blocklist = list(set([
    r'ad?url=https://youtube.com^', r'SCTE-35',
    r'iframe[src*="ad"]', r'div[id*="ad"]', r'div[class*="ad"]', r'section[class*="ad"]',
    r'div[class*="sponsor"]', r'div[class*="banner"]', r'div[id*="sponsor"]',
    r'div[class*="adsbygoogle"]', r'ins.adsbygoogle {', r'display: none !important',
    r'isibility: hidden !important', r'ad.', r'popup.', r'ytp-gated-actions-overlay',
    r"_video.mp4", r"ggpht.com", r'ytp-id-22', r'blob:', r'aria-haspopup', r'uploaded_content',
    r'<video[^>]*src="blob:https://www\.youtube\.com.*"></video>', r'aria-haspopup="true"',
    r'-ads-', r'xplayer-ads-block__callToAction--with-title', r'sfw-av-popup',
    r'data-role="auto-generated-banner-container"', r"allow-popups", r"xplayer-ads-block__link",
    r"prefetch", r"preconnect", r'ytp-free-preview-countdown-timer',
    r"ytd-offer-content-renderer", r'premium-log-overlay', "xnxx.gold",
    "header_adblock", "orbsrv.com", "justservingfiles.net", "trafficjunky", ".gold?pmsc",
    r'xnxx\.gold', r'\.gold\?pmsc', r'ad-model', r'blob:https://.*youtube\.com', r'ytp-popup',
    "_banner.png", "banner", "Banner", "Ad", "Ads", "advertisement",
    "trafficjunky.com", "media.trafficjunky.net", "ads.trafficjunky.com",
    "track.trafficjunky.com", "cdn.trafficjunky.com", "pb_iframe", "ht-cdn2.adtng.com",
    "adtng.com", "creatives", "warning-survey", "warning", "popup", "promoted",
    "jquery.min.js", "ad-footer", "ad-module", "gold-plate",
    "exo-native-widget-item-title", r'admodel', r'ad-model', r'ytp-o', r'adselector',
    r'ytp-', r'adsystem', r'orbsrv', r'afcdn', r'exo-native-widget',
    r'click\.php\?d=', "trafficfactory", "ads.trafficfactory", "track.trafficfactory",
    "cdn.trafficfactory", "Ads by TrafficFactory", r'loop', r'playsinline',
    'footerContentWrapper',
]))

# ============================
# LOGGING / HELPERS
# ============================
def log_message(message, color=Fore.WHITE):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{color}{timestamp} {message}{Style.RESET_ALL}")

def is_valid_domain(domain: str) -> bool:
    domain = domain.lower().strip(".")
    domain_regex = re.compile(r"^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,}$")
    return bool(domain_regex.match(domain))

def domain_in_allowlist(domain: str, allowset: set) -> bool:
    domain = domain.lower().strip(".")
    if domain in allowset:
        return True
    for allowed in allowset:
        if domain.endswith("." + allowed):
            return True
    return False

# ============================
# BLOCK/ALLOW LIST MANAGEMENT
# ============================
def fetch_blocklist(url):
    try:
        response = http.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        log_message(f"Failed to fetch blocklist from {url}: {e}", color=Fore.YELLOW)
        return ""

def parse_blocklist(raw_data):
    domains = set()
    for line in raw_data.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if "||" in line:
            domain = line.split("||")[1].split("^")[0]
            if is_valid_domain(domain):
                domains.add(domain)
        elif "$" in line:
            match = re.search(r"domain=([a-zA-Z0-9.-]+)", line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
        elif "." in line and is_valid_domain(line):
            domains.add(line)
    return domains

def load_file_domains(file_path: str) -> set:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return {line.strip().lower().strip(".") for line in f if is_valid_domain(line.strip())}
    except FileNotFoundError:
        return set()

def save_domains(file_path: str, domains: set):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            for d in sorted(domains):
                f.write(d + "\n")
    except Exception as e:
        log_message(f"Error saving {file_path}: {e}", color=Fore.RED)

def compact_discovered_blocklist():
    discovered = load_file_domains(discovered_file)
    if discovered:
        save_domains(discovered_file, discovered)
        log_message(f"Compacted discovered list to {len(discovered)} domains.", color=Fore.CYAN)

def update_blocklist():
    all_domains = set()
    for url in blocklist_urls:
        log_message(f"Fetching blocklist from {url}...", color=Fore.CYAN)
        raw_data = fetch_blocklist(url)
        if raw_data:
            domains = parse_blocklist(raw_data)
            log_message(f"Extracted {len(domains)} valid domains from {url}.", color=Fore.CYAN)
            all_domains.update(domains)

    local_discovered = load_file_domains(discovered_file)
    if local_discovered:
        log_message(f"Including {len(local_discovered)} locally discovered ad domains.", color=Fore.CYAN)
        all_domains.update(local_discovered)

    try:
        save_domains(blocklist_file, all_domains)
        log_message(f"Blocklist updated with {len(all_domains)} domains.", color=Fore.GREEN)
    except Exception as e:
        log_message(f"Error saving blocklist: {e}", color=Fore.RED)

def load_blocklist(file=blocklist_file):
    domains = load_file_domains(file)
    if not domains:
        log_message(f"Blocklist file '{file}' not found or empty.", color=Fore.YELLOW)
    return domains

def load_allowlist(file=allowlist_file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            return {line.strip().lower().strip(".") for line in f if line.strip()}
    except FileNotFoundError:
        log_message(f"Allowlist file '{file}' not found. Proceeding without allowlist.", color=Fore.YELLOW)
        return set()

# ============================
# HEURISTICS / DISCOVERY
# ============================
def extract_ad_related(data):
    try:
        decoded = data.decode('utf-8', errors='ignore')
    except Exception:
        return
    found = []
    for pattern in AD_CONTENT_PATTERNS:
        if re.search(pattern, decoded, re.IGNORECASE):
            found.append(pattern)
    if found:
        with open(ad_insights_log, "a", encoding="utf-8") as f:
            f.write(f"=== MATCH {datetime.datetime.now().isoformat()} ===\n")
            f.write(f"Patterns: {found}\n")
            f.write(f"Data snippet: {decoded[:5000]}\n\n")

def hostname_is_ad_candidate(domain: str) -> bool:
    d = domain.lower().strip(".")
    return any(k in d for k in AD_HOST_KEYWORDS)

def add_discovered_domain(domain: str):
    d = domain.lower().strip(".")
    if not is_valid_domain(d):
        return
    if domain_in_allowlist(d, allowlist_critical.union(allowlist)):
        return
    if d in blocklist:
        return
    with discover_lock:
        current = load_file_domains(discovered_file)
        if d in current:
            return
        current.add(d)
        save_domains(discovered_file, current)
        log_message(f"Discovered ad domain added: {d}", color=Fore.MAGENTA)

def is_blocked(domain):
    domain = domain.lower().strip('.')
    if domain_in_allowlist(domain, allowlist_critical) or domain in allowlist or domain_in_allowlist(domain, allowlist):
        log_message(f"ALLOWLISTED: {domain}", color=Fore.GREEN)
        return False
    if domain in blocklist:
        log_message(f"BLOCKED: {domain}", color=Fore.RED)
        return True
    for keyword in keyword_blocklist:
        if keyword in domain:
            log_message(f"BLOCKED (keyword match): {domain}", color=Fore.YELLOW)
            return True
    return False

# ============================
# CORE RESOLVER (shared by UDP & DoT)
# ============================
def resolve_query(query_bytes: bytes) -> bytes:
    try:
        request = DNSRecord.parse(query_bytes)
        qname = str(request.q.qname).strip('.').lower()

        # Auto-discovery pass
        if not is_blocked(qname) and hostname_is_ad_candidate(qname):
            add_discovered_domain(qname)

        if is_blocked(qname):
            reply = request.reply()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(SINK_IP)))
            return reply.pack()

        # Forward to upstream
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_sock:
            forward_sock.settimeout(3)
            forward_sock.sendto(query_bytes, UPSTREAM_DNS)
            response, _ = forward_sock.recvfrom(1000000)
            return response

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
# UDP SERVER (original behavior)
# ============================
def handle_request(data, addr, sock):
    try:
        extract_ad_related(data)  # keep original heuristic logging
        response = resolve_query(data)
        if response:
            sock.sendto(response, addr)
            client_ip = addr[0]
            active_users.add(client_ip)
    except Exception as e:
        log_message(f"Error handling request: {e}", color=Fore.RED)

def start_udp_server(host="0.0.0.0", port=53):
    log_message(f"Starting DNS (UDP) on {host}:{port}", color=Fore.CYAN)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((host, port))
        except PermissionError:
            log_message("Permission denied! Use a port above 1024 or run as administrator.", color=Fore.RED)
            return
        while True:
            try:
                data, addr = sock.recvfrom(1000000)
                handle_request(data, addr, sock)
            except KeyboardInterrupt:
                log_message("Shutting down UDP DNS.", color=Fore.CYAN)
                break
            except Exception as e:
                log_message(f"Non-fatal loop error: {e}", color=Fore.YELLOW)
                time.sleep(1)

# ============================
# DoT (DNS over TLS) SERVER
# ============================
class DoTServer(threading.Thread):
    """
    Minimal DoT (RFC 7858): DNS over TCP (2-byte length-prefixed) inside TLS.
    """

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

        # Ensure certs exist (auto-generate if missing)
        ensure_self_signed_cert(self.certfile, self.keyfile, DOT_HOSTNAME)

        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = tls_min_version
        if ciphers:
            self.ctx.set_ciphers(ciphers)
        self.ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

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
                    # DNS-over-TCP: 2-byte length prefix
                    lp = _recv_exact(tls, 2)
                    if not lp:
                        break
                    (msg_len,) = struct.unpack("!H", lp)
                    if msg_len == 0 or msg_len > 65535:
                        break
                    query = _recv_exact(tls, msg_len)
                    if not query:
                        break

                    response = resolve_query(query)
                    if not response:
                        break
                    tls.sendall(struct.pack("!H", len(response)) + response)
        except (ssl.SSLError, ConnectionError, socket.timeout):
            pass
        except Exception as e:
            log_message(f"DoT client error {addr}: {e}", color=Fore.YELLOW)
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

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

# ============================
# AUTO CERT GENERATION
# ============================
def ensure_self_signed_cert(certfile: str, keyfile: str, hostname: str = "localhost"):
    """
    Ensures cert/key exist. If missing, tries to create:
      1) Using 'cryptography' (preferred)
      2) Falling back to 'openssl' CLI if available
    """
    if os.path.exists(certfile) and os.path.exists(keyfile):
        return

    # Try Python 'cryptography' first
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import ipaddress

        log_message("Generating self-signed TLS cert via 'cryptography'...", color=Fore.YELLOW)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        alt_names = [x509.DNSName(hostname)]
        # If hostname looks like an IP, add IP SAN too
        try:
            ip = ipaddress.ip_address(hostname)
            alt_names.append(x509.IPAddress(ip))
        except Exception:
            pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )

        with open(keyfile, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(certfile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log_message(f"Self-signed cert created: {certfile}, {keyfile}", color=Fore.GREEN)
        return
    except Exception as e:
        log_message(f"'cryptography' not available or failed ({e}). Trying openssl CLI...", color=Fore.YELLOW)

    # Fallback to openssl CLI
    try:
        import subprocess, shutil
        if shutil.which("openssl") is None:
            raise RuntimeError("openssl not found on PATH")

        log_message("Generating self-signed TLS cert via 'openssl'...", color=Fore.YELLOW)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-keyout", keyfile, "-out", certfile, "-days", "365",
            "-subj", f"/CN={hostname}"
        ], check=True)
        log_message(f"Self-signed cert created: {certfile}, {keyfile}", color=Fore.GREEN)
        return
    except Exception as e:
        log_message(f"Could not auto-generate certs ({e}). DoT will be disabled. "
                    f"Provide {certfile}/{keyfile} to enable.", color=Fore.RED)

# ============================
# BACKGROUND: CURRENT USER COUNT WRITER
# ============================
def update_users_file():
    while True:
        try:
            with open("current_users.txt", "w", encoding="utf-8") as f:
                f.write(str(len(active_users)))
        except Exception as e:
            log_message(f"Error writing current_users.txt: {e}", color=Fore.YELLOW)
        time.sleep(360)

threading.Thread(target=update_users_file, daemon=True).start()

# ============================
# MAIN
# ============================
if __name__ == "__main__":
    try:
        # 1) Keep discovered list tight/clean
        compact_discovered_blocklist()

        log_message("Updating blocklist...", color=Fore.CYAN)
        # 2) Build the on-disk blocklist = remote lists + locally discovered
        update_blocklist()

        # 3) Load in-memory sets
        global blocklist, allowlist
        blocklist = load_blocklist()
        allowlist = load_allowlist()

        # 4) Start DoT if possible (auto-generates self-signed if missing)
        dot_started = False
        try:
            dot = DoTServer()
            dot.start()
            dot_started = True
            log_message(f"DoT {'ENABLED' if dot_started else 'DISABLED'} (TLS on :{DOT_PORT}).", color=Fore.GREEN if dot_started else Fore.YELLOW)
        except Exception as e:
            log_message(f"DoT disabled (TLS init failed): {e}", color=Fore.YELLOW)

        # 5) Run UDP server (foreground)
        start_udp_server()

    except KeyboardInterrupt:
        log_message("Shutting down.", color=Fore.CYAN)
    except Exception as e:
        log_message(f"FATAL ERROR: {e}", color=Fore.RED)
