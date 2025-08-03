import os
import requests
import socket
from dnslib import DNSRecord, QTYPE, RR, A
import re
import time
import threading
import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# created by: "Brian Cambron"
# Github https://github.com/BadInfluence69
# YouTube https://www.youtube.com/@BadInfluenceYT/videos
# Web site http://185.107.97.246/AdVault/



def extract_ad_related(data):
    try:
        decoded = data.decode('utf-8', errors='ignore')
    except Exception:
        return

    patterns = list(set([
        r'admodel', r'ad-model', r'ytp-o', r'adselector', r'ytp-', r'adsystem', r'orbsrv', r'afcdn',
        r'exo-native-widget', r'click\.php\?d=', r'loop', r'ytp-popup',
        r'blob:https://.*pornhub.com/', r'blob:https://.*youtube.com/', r'trafficfactory',
        r'aria-haspopup="true"', r'playinline', r'\.webp', r'\.php\?d=', r'xnxx\.gold', r'\.gold\?pmsc',
        r'header_adblock', r'session_token', r'-ads-', r'xplayer-ads-block__callToAction--with-title',
        r'sfw-av-popup', r'data-role="auto-generated-banner-container"', r'display.',
        r'<video[^>]*src="blob:https://www\.youtube\.com.*"></video>', r'ytp-gated-actions-overlay',
        r'_video.mp4', r'ggpht.com', r'ytp-id-22', r'blob:', r'aria-haspopup', r'uploaded_content',
        r'allow-popups', r"xplayer-ads-block__link", r'prefetch', r'preconnect',
        r'ytp-free-preview-countdown-timer', r"ytd-offer-content-renderer",
        r'premium-log-overlay', r'ad.', r'popup.',
    ]))  # deduped

    found = []
    for pattern in patterns:
        if re.search(pattern, decoded, re.IGNORECASE):
            found.append(pattern)

    if found:
        with open("ad_insights.txt", "a") as f:
            f.write(f"=== MATCH ===\n")
            f.write(f"Patterns: {found}\n")
            f.write(f"Data snippet: {decoded[:5000]}\n\n")

active_users = set()

def update_users_file():
    while True:
        with open("current_users.txt", "w") as f:
            f.write(str(len(active_users)))
        time.sleep(360)

threading.Thread(target=update_users_file, daemon=True).start()

blocklist_file = "dynamic_blocklist.txt"
allowlist_file = "allowlist.txt"

blocklist_urls = [
    "http://185.107.97.246/AdVault/dynamic_blocklist.txt",
    "http://185.107.97.246/AdVault/ad_insights.txt",
]

allowlist_critical = {
    "googlevideo.com", "youtube.com", "ytimg.com",
    "pirateproxy-bay.com", "i.ytimg.com", "s.ytimg.com",
    "lh3.googleusercontent.com", "yt3.ggpht.com",  # <-- Fixed missing comma
    "youtubei.googleapis.com", "chart.js", "AdVault",
    "tv.youtube.com", "ytp-player-content", "ytp-iv-player-content",
    "allow-storage-access-by-user-activation", "allow-scripts",
    "accounts.google.com"
}

keyword_blocklist = list(set([
    r'ad.', r'popup.', r'ytp-gated-actions-overlay', r"_video.mp4", r"ggpht.com",
    r'ytp-id-22', r'blob:', r'aria-haspopup', r'uploaded_content',
    r'<video[^>]*src="blob:https://www\.youtube\.com.*"></video>', r'aria-haspopup="true"',
    r'-ads-', r'xplayer-ads-block__callToAction--with-title', r'sfw-av-popup',
    r'data-role="auto-generated-banner-container"', r"allow-popups", r"xplayer-ads-block__link",
    r"prefetch", r"preconnect", r'ytp-free-preview-countdown-timer',
    r"ytd-offer-content-renderer", r'premium-log-overlay', "xnxx.gold",
    "header_adblock", "orbsrv.com", "justservingfiles.net", "trafficjunky", ".gold?pmsc",
    r'xnxx\.gold', r'\.gold\?pmsc', r'ad-model', r'blob:https://.*youtube\.com',
    r'ytp-popup', "_banner.png", "banner", "Banner", "Ad", "Ads", "advertisement",
    "trafficjunky.com", "media.trafficjunky.net", "ads.trafficjunky.com",
    "track.trafficjunky.com", "cdn.trafficjunky.com", "pb_iframe", "ht-cdn2.adtng.com",
    "adtng.com", "creatives", "warning-survey", "warning", "popup", "promoted",
    "jquery.min.js", "ad-footer", "ad-module", "gold-plate",
    "exo-native-widget-item-title", r'admodel', r'ad-model', r'ytp-o', r'adselector',
    r'ytp-', r'adsystem', r'orbsrv', r'afcdn', r'exo-native-widget',
    r'click\.php\?d=', "trafficfactory", "ads.trafficfactory", "track.trafficfactory",
    "cdn.trafficfactory", "Ads by TrafficFactory", r'loop', r'playsinline',
    r'footerContentWrapper',
]))

def log_message(message, color=Fore.WHITE):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{color}{timestamp} {message}{Style.RESET_ALL}")

def is_valid_domain(domain):
    domain_regex = re.compile(r"^(?:[a-zA-Z0-9-]{1,63}\.){1,}[a-zA-Z]{2,}$")
    return domain_regex.match(domain) is not None

def fetch_blocklist(url):
    try:
        response = requests.get(url, timeout=10)
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

def update_blocklist():
    all_domains = set()
    for url in blocklist_urls:
        log_message(f"Fetching blocklist from {url}...", color=Fore.CYAN)
        raw_data = fetch_blocklist(url)
        if raw_data:
            domains = parse_blocklist(raw_data)
            log_message(f"Extracted {len(domains)} valid domains from {url}.", color=Fore.CYAN)
            all_domains.update(domains)
    try:
        with open(blocklist_file, "w", encoding="utf-8") as f:
            for domain in sorted(all_domains):
                f.write(domain + "\n")
        log_message(f"Blocklist updated with {len(all_domains)} domains.", color=Fore.GREEN)
    except Exception as e:
        log_message(f"Error saving blocklist: {e}", color=Fore.RED)

def load_blocklist(file=blocklist_file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if is_valid_domain(line.strip())}
    except FileNotFoundError:
        log_message(f"Blocklist file '{file}' not found.", color=Fore.YELLOW)
        return set()

def load_allowlist(file=allowlist_file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        log_message(f"Allowlist file '{file}' not found. Proceeding without allowlist.", color=Fore.YELLOW)
        return set()

def is_blocked(domain):
    domain = domain.lower().strip('.')
    if domain in allowlist_critical or domain in allowlist:
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

def handle_request(data, addr, sock):
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname).strip('.')
        reply = request.reply()
        if is_blocked(qname):
            reply.add_answer(RR(qname, QTYPE.A, rdata=A("185.107.97.246")))
            sock.sendto(reply.pack(), addr)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward_sock:
                forward_sock.settimeout(3)
                forward_sock.sendto(data, ("8.8.8.8", 53))
                response, _ = forward_sock.recvfrom(1000000000)
                sock.sendto(response, addr)
    except Exception as e:
        log_message(f"Error handling request: {e}", color=Fore.RED)

def start_server(host="0.0.0.0", port=53):
    log_message(f"Starting DNS server on {host}:{port}", color=Fore.CYAN)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((host, port))
        except PermissionError:
            log_message("Permission denied! Use a port above 1024 or run as administrator.", color=Fore.RED)
            return
        while True:
            try:
                data, addr = sock.recvfrom(1000000000)
                extract_ad_related(data)
                handle_request(data, addr, sock)
                client_ip = addr[0]
                active_users.add(client_ip)
            except KeyboardInterrupt:
                log_message("Shutting down the DNS server.", color=Fore.CYAN)
                break
            except Exception as e:
                log_message(f"Non-fatal loop error: {e}", color=Fore.YELLOW)
                time.sleep(1)

if __name__ == "__main__":
    try:
        log_message("Updating blocklist...", color=Fore.CYAN)
        update_blocklist()
        global blocklist, allowlist
        blocklist = load_blocklist()
        allowlist = load_allowlist()
        start_server()
    except Exception as e:
        log_message(f"FATAL ERROR: {e}", color=Fore.RED)
