#!/data/data/com.termux/files/usr/bin/python
import os
import subprocess
import re
import time
import sys
import socket
from collections import defaultdict

# ---------- CONFIG ----------
INTERFACE = "wlan0"
USE_WASH = False

# ---------- COLORS ----------
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

FLAG_FILE = os.path.expanduser("~/.wps_scanner_installed")

# ---------- DEPENDENCIES ----------
def command_exists(cmd):
    return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def install_packages():
    if os.path.exists(FLAG_FILE):
        return
    print(f"{YELLOW}[*] First launch – installing dependencies...{RESET}")
    subprocess.run(["pkg", "update", "-y"], check=False)
    subprocess.run(["pkg", "install", "-y", "iw", "reaver"], check=False)
    with open(FLAG_FILE, "w") as f:
        f.write("installed")
    print(f"{GREEN}[+] Dependencies installed. Ready.{RESET}\n")

def clear_screen():
    os.system('clear')

# ---------- BANNER ----------
def show_banner():
    clear_screen()
    try:
        cols = os.get_terminal_size().columns
    except:
        cols = 80

    banner_lines = [
        "Darkhub security check Scanner v2.0 (Root)"
    ]
    max_len = max(len(line) for line in banner_lines) + 4
    if cols >= max_len:
        top_border = "  ╔" + "═" * (len(banner_lines[0]) - 4) + "╗"
        bottom_border = "  ╚" + "═" * (len(banner_lines[0]) - 4) + "╝"
        padding = (cols - len(top_border)) // 2
        print(f"{RED}{BOLD}" + " " * max(0, padding) + top_border + f"{RESET}")
        for line in banner_lines:
            if line == "":
                print()
                continue
            side_border = "  ║" + line + "║"
            padding = (cols - len(side_border)) // 2
            print(f"{RED}{BOLD}" + " " * max(0, padding) + side_border + f"{RESET}")
        print(f"{RED}{BOLD}" + " " * max(0, padding) + bottom_border + f"{RESET}")
    else:
        print(f"{RED}{BOLD}Darkhub WPS Scanner v2.0{RESET}")
    time.sleep(2)
    clear_screen()

# ---------- SCAN WITH iw ----------
def scan_networks():
    if not command_exists("iw"):
        print(f"{RED}[!] iw not installed – please run the script again to install it.{RESET}")
        return []
    try:
        cmd = ["iw", "dev", INTERFACE, "scan"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"{RED}[!] iw scan failed. Are you root? Try: su -c 'iw dev wlan0 scan'{RESET}")
            return []
        output = result.stdout

        bss_blocks = re.split(r'BSS\s+([0-9a-fA-F:]{17})', output)
        networks = []
        for i in range(1, len(bss_blocks), 2):
            bssid = bss_blocks[i].strip()
            block = bss_blocks[i+1]
            ssid_match = re.search(r'SSID:\s*(.+)', block)
            ssid = ssid_match.group(1).strip() if ssid_match else "Hidden"
            signal_match = re.search(r'signal:\s*(-?\d+)', block)
            signal = signal_match.group(1) if signal_match else "0"

            security = "Open"
            if "RSN:" in block:
                if re.search(r'SAE|WPA3', block, re.IGNORECASE):
                    security = "WPA3"
                else:
                    security = "WPA2"
            elif "WPA:" in block:
                security = "WPA"
            elif "WEP:" in block:
                security = "WEP"

            wps_present = "WPS" in block.upper()
            pmf = False
            if "MFP required" in block or "PMF" in block or "MFP capable" in block:
                pmf = True
            hidden = (ssid == "Hidden")

            networks.append({
                'ssid': ssid,
                'bssid': bssid,
                'signal': signal,
                'security': security,
                'wps_present': wps_present,
                'pmf': pmf,
                'hidden': hidden,
                'fake': False
            })

        ssid_to_bssids = defaultdict(set)
        for net in networks:
            if not net['hidden']:
                ssid_to_bssids[net['ssid']].add(net['bssid'])

        for net in networks:
            if not net['hidden'] and len(ssid_to_bssids[net['ssid']]) > 1:
                net['fake'] = True

        return networks
    except Exception as e:
        print(f"{RED}[!] Scan error: {e}{RESET}")
        return []

def display_networks(networks):
    clear_screen()
    print(f"{BOLD}{GREEN}========== Available Wi‑Fi Networks (via {INTERFACE}) =========={RESET}")
    print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'Signal':<8} {'Security':<8} {'WPS':<5} {'PMF':<5} {'FAKE'}")
    print("-" * 90)
    for idx, net in enumerate(networks, 1):
        wps_flag = "YES" if net['wps_present'] else "NO"
        pmf_flag = "YES" if net.get('pmf', False) else "NO"
        fake_flag = "YES" if net.get('fake', False) else "NO"
        print(f"{idx:<3} {net['ssid'][:24]:<25} {net['bssid']:<18} {net['signal']:<8} {net['security']:<8} {wps_flag:<5} {pmf_flag:<5} {fake_flag}")
    print("-" * 90)
    print("Enter number to select, 'm' for multi‑SSID/Evil Twin detection, 'h' for help, 'r' to rescan, 'q' to quit")

# ---------- MULTIPLE SSIDs & EVIL TWIN DETECTION ----------
def detect_multiple_ssids(networks):
    clear_screen()
    bssid_map = defaultdict(list)
    for net in networks:
        bssid_map[net['bssid']].append(net['ssid'])
    print(f"{YELLOW}--- Multiple SSIDs per BSSID ---{RESET}")
    found = False
    for bssid, ssids in bssid_map.items():
        if len(set(ssids)) > 1:
            print(f"BSSID {bssid} broadcasts multiple SSIDs: {', '.join(set(ssids))}")
            found = True
    if not found:
        print("No BSSID with multiple SSIDs detected.")
    print()

    ssid_map = defaultdict(list)
    for net in networks:
        if not net['hidden']:
            ssid_map[net['ssid']].append(net['bssid'])
    print(f"{YELLOW}--- Potential Evil Twin SSIDs ---{RESET}")
    found = False
    for ssid, bssids in ssid_map.items():
        if len(set(bssids)) > 1:
            print(f"SSID '{ssid}' appears with multiple BSSIDs: {', '.join(set(bssids))}")
            print("   This could indicate an Evil Twin attack.")
            found = True
    if not found:
        print("No duplicate SSIDs detected.")
    print()
    input(f"{YELLOW}Press Enter to return...{RESET}")

# ---------- HELP MENU ----------
def help_menu():
    clear_screen()
    print(f"{BOLD}{GREEN}========== Help =========={RESET}")
    print("Main menu commands:")
    print("  <number> - Select a network to run all tests")
    print("  m        - Show multiple SSID / Evil Twin detection")
    print("  r        - Rescan networks")
    print("  q        - Quit")
    print("  h        - Show this help")
    print("\nAfter selecting a network, the script automatically runs:")
    print("  - Detailed information")
    print("  - Passive vulnerability checks (WPS, KRACK, Pixie Dust, Deauth)")
    print("  - Active security checks (only if connected to that network):")
    print("      * UPnP status (SSDP probe)")
    print("      * Remote management / admin page probe")
    print("      * Router open ports scan")
    print("      * Client isolation test")
    print("  - Brutal security rating (0–10)")
    print("  - 15-second countdown before returning to main menu")
    input(f"{YELLOW}Press Enter to return...{RESET}")

# ---------- SECURITY RATING (BRUTAL) ----------
def security_rating(network):
    score = 10
    details = []

    if network['security'] == "WPA3":
        details.append("WPA3 (0) - strong")
    elif network['security'] == "WPA2":
        score -= 4
        details.append("WPA2 (-4) KRACK risk")
    elif network['security'] == "WPA":
        score -= 6
        details.append("WPA (-6) TKIP weak")
    elif network['security'] == "WEP":
        score -= 8
        details.append("WEP (-8) broken")
    else:
        score -= 10
        details.append("Open (-10) no encryption")

    if not network.get('pmf', False):
        score -= 2
        details.append("No PMF (-2) deauth risk")
    else:
        details.append("PMF enabled (0)")

    if network['wps_present']:
        score -= 2
        details.append("WPS enabled (-2) brute-force risk")
    else:
        details.append("WPS disabled (0)")

    if network.get('hidden', False):
        score -= 1
        details.append("Hidden SSID (-1) obscurity only")

    if network.get('fake', False):
        score -= 3
        details.append("Possible Evil Twin (-3)")

    score = max(0, min(10, score))
    return score, details

# ---------- DETAILS ----------
def show_details(network):
    print(f"{BOLD}{GREEN}========== Details for {network['ssid']} =========={RESET}")
    print(f"BSSID     : {network['bssid']}")
    print(f"Signal    : {network['signal']} dBm")
    print(f"Security  : {network['security']}")
    print(f"WPS       : {'ENABLED' if network['wps_present'] else 'NOT DETECTED'}")
    print(f"PMF       : {'YES' if network.get('pmf', False) else 'NO'}")
    if network.get('hidden', False):
        print("SSID      : Hidden (not broadcast)")
    if network.get('fake', False):
        print(f"{RED}Status    : POSSIBLE FAKE / EVIL TWIN{RESET}")
    print()

# ---------- ACTIVE CHECKS ----------
def is_connected_to_ssid(ssid):
    try:
        result = subprocess.run(["iw", "dev", INTERFACE, "link"], capture_output=True, text=True, timeout=5)
        out = result.stdout
        if "Not connected" in out:
            return False
        m = re.search(r'SSID:\s*(.+)', out)
        return m and m.group(1).strip() == ssid
    except Exception:
        return False

def get_gateway():
    try:
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.split()[2]
    except Exception:
        pass
    return None

def get_local_subnet():
    try:
        result = subprocess.run(["ip", "-4", "addr", "show", INTERFACE], capture_output=True, text=True, timeout=5)
        m = re.search(r'inet\s+(\d+\.\d+\.\d+)\.\d+/\d+', result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def check_upnp(timeout=3):
    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 1\r\n'
        'ST: upnp:rootdevice\r\n'
        '\r\n'
    ).encode()
    replies = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(msg, ("239.255.255.250", 1900))
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                replies.append((addr[0], data.decode(errors='ignore')))
        except socket.timeout:
            pass
        finally:
            sock.close()
    except Exception:
        pass
    return replies

def check_http_ports(gateway):
    import urllib.request
    import ssl
    results = {}
    for port in [80, 443, 8080, 8443]:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{gateway}:{port}/"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                html = resp.read(2048).decode(errors='ignore')
                server = resp.headers.get("Server", "")
                m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
                title = m.group(1).strip() if m else ""
                results[port] = (server, title)
        except Exception:
            pass
    return results

def check_open_ports(gateway, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((gateway, port), timeout=2):
                open_ports.append(port)
        except Exception:
            pass
    return open_ports

def check_client_isolation(subnet):
    import random
    reachable = []
    for _ in range(5):
        last = random.randint(2, 254)
        ip = f"{subnet}.{last}"
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=3)
            if r.returncode == 0:
                reachable.append(ip)
        except Exception:
            pass
    return reachable

def active_security_checks(network):
    print(f"\n{BOLD}{YELLOW}--- Active Security Assessment ---{RESET}")

    if not is_connected_to_ssid(network['ssid']):
        print(f"{YELLOW}[!] Not connected to '{network['ssid']}' — active checks skipped.{RESET}")
        print(f"{YELLOW}    Connect to this network and rerun to test: UPnP, remote management, open ports, client isolation.{RESET}")
        return

    gateway = get_gateway()
    subnet = get_local_subnet()

    if not gateway:
        print(f"{YELLOW}[!] No default gateway detected — active checks skipped.{RESET}")
        return

    print(f"{GREEN}[+] Connected. Gateway: {gateway}{RESET}")

    # --- UPnP ---
    print(f"\n{BOLD}UPnP Status:{RESET}")
    upnp = check_upnp()
    if upnp:
        print(f"{RED}[!] UPnP ENABLED — {len(upnp)} device(s) responded:{RESET}")
        for addr, _ in upnp[:3]:
            print(f"    {addr}")
        print(f"{YELLOW}    Risk: UPnP can expose internal services to the internet.{RESET}")
    else:
        print(f"{GREEN}[+] UPnP appears disabled or unresponsive.{RESET}")

    # --- Remote management / admin page ---
    print(f"\n{BOLD}Remote Management / Admin Page:{RESET}")
    http_results = check_http_ports(gateway)
    if http_results:
        for port, (server, title) in http_results.items():
            print(f"{YELLOW}[!] Port {port}: OPEN — Server: {server or 'unknown'} | Title: {title or 'N/A'}{RESET}")
            if server and re.search(r'(Apache/1\.|Apache/2\.[0-2]|nginx/0|nginx/1\.[0-9]|lighttpd/1\.[0-3])', server):
                print(f"{RED}    Firmware hint: server header '{server}' is outdated — likely unpatched firmware.{RESET}")
        print(f"{YELLOW}    Risk: Router admin interface reachable on LAN. Ensure it is NOT exposed to WAN.{RESET}")
    else:
        print(f"{GREEN}[+] No common HTTP/HTTPS admin ports responded on {gateway}.{RESET}")

    # --- Open ports ---
    print(f"\n{BOLD}Router Open Ports (common services):{RESET}")
    common_ports = [21, 22, 23, 53, 80, 443, 445, 7547, 8080, 8443]
    open_ports = check_open_ports(gateway, common_ports)
    if open_ports:
        print(f"{YELLOW}[!] Open ports: {', '.join(map(str, open_ports))}{RESET}")
        risky = [p for p in open_ports if p in (21, 22, 23, 445, 7547)]
        if risky:
            print(f"{RED}    HIGH RISK: {', '.join(map(str, risky))} — often exploited (Telnet, FTP, SMB, TR-069).{RESET}")
    else:
        print(f"{GREEN}[+] No common ports open (or all filtered).{RESET}")

    # --- Client isolation ---
    print(f"\n{BOLD}Client Isolation Test:{RESET}")
    if subnet:
        reachable = check_client_isolation(subnet)
        if reachable:
            print(f"{RED}[!] Client isolation is OFF — other clients reachable: {', '.join(reachable)}{RESET}")
            print(f"{YELLOW}    Risk: Any device on this Wi-Fi can reach your device directly.{RESET}")
        else:
            print(f"{YELLOW}[?] No other clients responded — isolation may be ON, or no other clients are online.{RESET}")
    else:
        print(f"{YELLOW}[?] Could not determine local subnet.{RESET}")

# ---------- PASSIVE VULNERABILITY CHECKS ----------
def vulnerability_checks(network):
    print(f"{BOLD}{GREEN}===== Passive Vulnerability Checks for {network['ssid']} ({network['bssid']}) ====={RESET}")

    # WPS
    if network['wps_present']:
        print(f"{GREEN}[+] WPS is ENABLED.{RESET}")
    else:
        print(f"{GREEN}[+] WPS is disabled (or not detected).{RESET}")

    # KRACK
    if network['security'] in ["WPA", "WPA2"]:
        print(f"{YELLOW}[!] KRACK Vulnerability: Network uses {network['security']}. WPA/WPA2 may be vulnerable to KRACK if devices are not patched.{RESET}")
    elif network['security'] == "WPA3":
        print(f"{GREEN}[+] Not vulnerable to KRACK (WPA3).{RESET}")
    else:
        print(f"{GREEN}[+] Not vulnerable to KRACK (not WPA/WPA2).{RESET}")

    # Null PIN
    if network['wps_present']:
        print(f"{YELLOW}[!] Null PIN: WPS enabled. Susceptible if PIN is easily guessable.{RESET}")
    else:
        print(f"{GREEN}[+] No Null PIN risk (WPS disabled).{RESET}")

    # Pixie Dust
    if network['wps_present']:
        if command_exists("pixiewps"):
            print(f"{YELLOW}[!] Pixie Dust: pixiewps installed — can attempt Pixie Dust with monitor mode.{RESET}")
        else:
            print(f"{YELLOW}[!] Pixie Dust: pixiewps not installed. Install with 'pkg install pixiewps'.{RESET}")
    else:
        print(f"{GREEN}[+] No Pixie Dust risk (WPS disabled).{RESET}")

    # Deauth
    if network['security'] in ["Open", "WEP"]:
        print(f"{RED}[!] Deauth Vulnerability: OPEN/WEP networks are inherently vulnerable to deauthentication attacks.{RESET}")
    elif not network.get('pmf', False):
        print(f"{YELLOW}[!] Deauth Vulnerability: PMF not detected. Network may be vulnerable to deauthentication attacks.{RESET}")
    else:
        print(f"{GREEN}[+] Deauth Protection: PMF is enabled, reducing deauthentication attacks.{RESET}")

    # Passive brutal assessment (only what we can see)
    print(f"\n{BOLD}{YELLOW}--- Brutal Passive Security Assessment ---{RESET}")
    if network['security'] in ["WEP", "Open"]:
        print(f"{RED}[CRITICAL] Weak Encryption: {network['security']} can be cracked in minutes.{RESET}")
    elif network['security'] == "WPA":
        print(f"{RED}[HIGH] Weak Encryption: WPA uses TKIP, deprecated and vulnerable.{RESET}")
    elif network['security'] == "WPA2":
        print(f"{YELLOW}[MEDIUM] Encryption: WPA2 has known weaknesses (KRACK).{RESET}")
    elif network['security'] == "WPA3":
        print(f"{GREEN}[STRONG] Encryption: WPA3 with SAE is secure.{RESET}")

    if network.get('hidden', False):
        print(f"{YELLOW}[INFO] Hidden SSID: Clients may reveal it in probe requests. Not strong security.{RESET}")
    else:
        print(f"{GREEN}[INFO] SSID Broadcast: SSID broadcast normally.{RESET}")

    if network['security'] in ["Open", "WEP"]:
        print(f"{RED}[HIGH] Session Hijacking: Open/WEP allows easy session hijacking.{RESET}")
    elif network['security'] == "WPA":
        print(f"{YELLOW}[MEDIUM] Session Hijacking: WPA/TKIP may be vulnerable.{RESET}")
    else:
        print(f"{GREEN}[LOW] Session Hijacking: Strong encryption reduces risk.{RESET}")

    if network['security'] == "Open":
        print(f"{RED}[CRITICAL] Open Network: No encryption; all traffic visible.{RESET}")
    else:
        print(f"{GREEN}[OK] Not an open network.{RESET}")

    print(f"{YELLOW}[INFO] Beacon Frames: Reveal BSSID, channel, capabilities — inherent to Wi-Fi.{RESET}")

    # ---- ACTIVE CHECKS ----
    active_security_checks(network)

    # ---- BRUTAL RATING ----
    score, details = security_rating(network)
    if score >= 8:
        color = GREEN
    elif score >= 5:
        color = YELLOW
    else:
        color = RED
    print(f"\n{BOLD}Security Rating: {color}{score}/10{RESET}")
    for d in details:
        print(f"  - {d}")
    print()

# ---------- GATEWAY PING ----------
def ping_gateway():
    print(f"{BOLD}{GREEN}===== Gateway Ping ====={RESET}")
    try:
        result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            gateway = result.stdout.split()[2]
            print(f"Detected current default gateway: {gateway}")
            print(f"Pinging {gateway} ...")
            ping_result = subprocess.run(["ping", "-c", "4", gateway], capture_output=True, text=True, timeout=15)
            print(ping_result.stdout)
            if ping_result.returncode == 0:
                print(f"{GREEN}[+] Host is reachable.{RESET}")
            else:
                print(f"{RED}[-] Host is unreachable or ping blocked.{RESET}")
        else:
            print(f"{YELLOW}[!] Not connected to any network; skipping gateway ping.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Ping error: {e}{RESET}")
    print()

# ---------- COUNTDOWN ----------
def countdown_timer(seconds):
    for i in range(seconds, 0, -1):
        print(f"\r{YELLOW}Returning to main menu in {i} seconds...{RESET}", end="", flush=True)
        time.sleep(1)
    print("\r\033[K", end="")  # ANSI clear-line — no residual characters

# ---------- MAIN ----------
def main():
    show_banner()
    install_packages()
    if os.geteuid() != 0:
        print(f"{RED}[!] This script needs root to scan with iw. Run with: tsu  python scanner.py{RESET}")
        sys.exit(1)

    while True:
        networks = scan_networks()
        if not networks:
            print(f"{RED}No networks found. Make sure WiFi is on and interface {INTERFACE} exists.{RESET}")
            time.sleep(3)
            continue

        display_networks(networks)
        choice = input("> ").strip().lower()

        if choice == 'q':
            print(f"{GREEN}Bye!stay with Darkhub{RESET}")
            break
        elif choice == 'r':
            continue
        elif choice == 'h':
            help_menu()
            continue
        elif choice == 'm':
            detect_multiple_ssids(networks)
            continue
        elif choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                selected = networks[idx-1]
                show_details(selected)
                vulnerability_checks(selected)
                ping_gateway()
                countdown_timer(15)
            else:
                print(f"{RED}Invalid number.{RESET}")
                time.sleep(1)
        else:
            print(f"{RED}Invalid input.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
