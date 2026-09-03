1#!/data/data/com.termux/files/usr/bin/python
import os
import subprocess
import re
import time
import sys

# ---------- CONFIG ----------
INTERFACE = "wlan0"          # Change if your Wi-Fi interface is different
USE_WASH = False             # Set to True only if you have monitor mode and reaver

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
    subprocess.run(["pkg", "install", "-y", "iw", "reaver"], check=False)  # reaver for wash
    with open(FLAG_FILE, "w") as f:
        f.write("installed")
    print(f"{GREEN}[+] Dependencies installed. Ready.{RESET}\n")

def clear_screen():
    os.system('clear')

def wait_enter():
    input(f"{YELLOW}Press Enter to continue...{RESET}")

# ---------- SCAN WITH iw ----------
def scan_networks():
    """
    Scan using 'iw dev wlan0 scan' and parse output.
    Returns list of dicts: ssid, bssid, signal, security, wps_present
    """
    if not command_exists("iw"):
        print(f"{RED}[!] iw not installed – please run the script again to install it.{RESET}")
        return []
    try:
        # Run scan (needs root)
        cmd = ["iw", "dev", INTERFACE, "scan"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"{RED}[!] iw scan failed. Are you root? Try: su -c 'iw dev wlan0 scan'{RESET}")
            return []
        output = result.stdout

        # Split output per BSS
        bss_blocks = re.split(r'BSS\s+([0-9a-fA-F:]{17})', output)
        networks = []
        for i in range(1, len(bss_blocks), 2):
            bssid = bss_blocks[i].strip()
            block = bss_blocks[i+1]
            # Extract SSID
            ssid_match = re.search(r'SSID:\s*(.+)', block)
            ssid = ssid_match.group(1).strip() if ssid_match else "Hidden"
            # Extract signal (dBm)
            signal_match = re.search(r'signal:\s*(-?\d+)', block)
            signal = signal_match.group(1) if signal_match else "0"
            # Extract security (WPA/WPA2/WEP/Open)
            # Usually after "RSN:" or "WPA:" or "WEP:"
            security = "Open"
            if "RSN:" in block:
                security = "WPA2"
            elif "WPA:" in block:
                security = "WPA"
            elif "WEP:" in block:
                security = "WEP"
            # Check WPS presence: look for "WPS" in the block
            wps_present = "WPS" in block.upper()
            networks.append({
                'ssid': ssid,
                'bssid': bssid,
                'signal': signal,
                'security': security,
                'wps_present': wps_present
            })
        return networks
    except Exception as e:
        print(f"{RED}[!] Scan error: {e}{RESET}")
        return []

def display_networks(networks):
    clear_screen()
    print(f"{BOLD}{GREEN}========== Available Wi‑Fi Networks (via {INTERFACE}) =========={RESET}")
    print(f"{'#':<3} {'SSID':<25} {'BSSID':<18} {'Signal':<8} {'Security':<8} {'WPS'}")
    print("-" * 75)
    for idx, net in enumerate(networks, 1):
        wps_flag = "YES" if net['wps_present'] else "NO"
        print(f"{idx:<3} {net['ssid'][:24]:<25} {net['bssid']:<18} {net['signal']:<8} {net['security']:<8} {wps_flag}")
    print("-" * 75)
    print("Enter number to select, 'r' to rescan, 'q' to quit")

# ---------- CHECK WPS DETAILS ----------
def show_details(network):
    clear_screen()
    print(f"{BOLD}{GREEN}========== Details for {network['ssid']} =========={RESET}")
    print(f"BSSID     : {network['bssid']}")
    print(f"Signal    : {network['signal']} dBm")
    print(f"Security  : {network['security']}")
    print(f"WPS       : {'ENABLED' if network['wps_present'] else 'NOT DETECTED'}")

    # If WPS is enabled, show extra info from the scan (if any)
    if network['wps_present']:
        # Re‑scan to get full WPS details (vendor, version, etc.) if needed
        try:
            cmd = ["iw", "dev", INTERFACE, "scan", "|", "grep", "-A10", network['bssid']]
            # We'll just run a full scan and extract the block again
            result = subprocess.run(["iw", "dev", INTERFACE, "scan"], capture_output=True, text=True, timeout=10)
            output = result.stdout
            # Find the block for this BSSID
            pattern = r'BSS\s+' + re.escape(network['bssid']) + r'(.*?)(?=BSS\s+[0-9a-fA-F:]{17}|$)'
            match = re.search(pattern, output, re.DOTALL)
            if match:
                block = match.group(1)
                # Extract WPS tags
                wps_lines = re.findall(r'.*WPS.*', block, re.IGNORECASE)
                if wps_lines:
                    print("\n--- WPS Details ---")
                    for line in wps_lines[:5]:
                        print(line.strip())
        except Exception:
            pass

    # Optional: use wash if enabled
    if USE_WASH and command_exists("wash") and os.geteuid() == 0:
        print("\n--- Running wash (requires monitor mode) ---")
        try:
            # Enable monitor mode on a separate interface (or use existing)
            # We'll assume you already have monitor mode on mon0
            mon_iface = "mon0"
            # If not, we could auto-enable, but we'll warn
            if not os.path.exists(f"/sys/class/net/{mon_iface}"):
                print("[!] Monitor interface not found. Please run: airmon-ng start wlan0")
            else:
                result = subprocess.run(
                    ["wash", "-i", mon_iface, "--bssid", network['bssid']],
                    capture_output=True, text=True, timeout=15
                )
                if result.stdout:
                    print(result.stdout.strip())
        except Exception as e:
            print(f"[!] wash error: {e}")

# ---------- MAIN ----------
def main():
    # Centered banner
    try:
        cols = os.get_terminal_size().columns
    except:
        cols = 80

    clear_screen()
    banner = [
        "   ██████  █████  ██████  ██   ██ ██    ██ ██████",
        "   ██   ██ ██   ██ ██   ██ ██   ██ ██    ██ ██   ██",
        "   ██   ██ ███████ ██████  ███████ ██    ██ ██████",
        "   ██   ██ ██   ██ ██   ██ ██   ██ ██    ██ ██   ██",
        "   ██████  ██   ██ ██   ██ ██   ██  ██████  ██████",
        "",
        "              Darkhub WPS Scanner v1.0 (Root)"
    ]
    print(f"{GREEN}{BOLD}")
    for line in banner:
        padding = (cols - len(line)) // 2
        print(" " * max(0, padding) + line)
    print(f"{RESET}")
    time.sleep(3)
    clear_screen()

    # Install deps
    install_packages()

    # Check if root
    if os.geteuid() != 0:
        print(f"{RED}[!] This script needs root to scan with iw. Run with: su -c python wps_scanner_root.py{RESET}")
        sys.exit(1)

    # Main loop
    while True:
        networks = scan_networks()
        if not networks:
            print(f"{RED}No networks found. Make sure WiFi is on and interface {INTERFACE} exists.{RESET}")
            print(f"{YELLOW}Try: iw dev{RESET}")
            time.sleep(3)
            continue

        display_networks(networks)
        choice = input("> ").strip().lower()

        if choice == 'q':
            print(f"{GREEN}Bye!{RESET}")
            break
        elif choice == 'r':
            continue
        elif choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                show_details(networks[idx-1])
                wait_enter()
            else:
                print(f"{RED}Invalid number.{RESET}")
                time.sleep(1)
        else:
            print(f"{RED}Invalid input.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    main()
