
#!/usr/bin/env python3
"""
Wi-Fi Analyzer Tool
Scans and displays nearby Wi-Fi networks with signal strength and security info.
Supports Windows, Linux, and macOS.
"""

import subprocess
import platform
import re
import os
from datetime import datetime


def clear():
    os.system('cls' if platform.system() == 'Windows' else 'clear')


def signal_to_bar(signal_percent):
    """Convert signal percentage to visual bar."""
    filled = int(signal_percent / 10)
    bar = '█' * filled + '░' * (10 - filled)
    return bar


def signal_quality(signal_percent):
    """Rate signal quality."""
    if signal_percent >= 80:
        return '🟢 Excellent'
    elif signal_percent >= 60:
        return '🟡 Good'
    elif signal_percent >= 40:
        return '🟠 Fair'
    else:
        return '🔴 Poor'


def dbm_to_percent(dbm):
    """Convert dBm to percentage (approx)."""
    dbm = max(min(dbm, -30), -100)
    return int(2 * (dbm + 100))


# ─────────────────────────────────────────────
# Windows
# ─────────────────────────────────────────────
def scan_windows():
    try:
        result = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
            encoding='utf-8', errors='ignore'
        )
    except Exception as e:
        print(f"[Error] Could not run netsh: {e}")
        return []

    networks = []
    blocks = result.split('\n\n')

    for block in blocks:
        ssid_match = re.search(r'SSID\s+\d+\s+:\s+(.+)', block)
        auth_match = re.search(r'Authentication\s+:\s+(.+)', block)
        signal_match = re.search(r'Signal\s+:\s+(\d+)%', block)
        channel_match = re.search(r'Channel\s+:\s+(\d+)', block)
        bssid_match = re.search(r'BSSID\s+\d+\s+:\s+([0-9a-fA-F:]+)', block)

        if ssid_match:
            signal = int(signal_match.group(1)) if signal_match else 0
            networks.append({
                'ssid': ssid_match.group(1).strip(),
                'bssid': bssid_match.group(1).strip() if bssid_match else 'N/A',
                'signal': signal,
                'security': auth_match.group(1).strip() if auth_match else 'Unknown',
                'channel': channel_match.group(1).strip() if channel_match else 'N/A',
            })

    return networks


# ─────────────────────────────────────────────
# Linux
# ─────────────────────────────────────────────
def scan_linux():
    networks = []

    # Try nmcli first
    try:
        result = subprocess.check_output(
            ['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,SECURITY,CHAN', 'dev', 'wifi'],
            encoding='utf-8', errors='ignore'
        )
        for line in result.strip().split('\n'):
            parts = line.split(':')
            if len(parts) >= 5:
                try:
                    signal = int(parts[2])
                except ValueError:
                    signal = 0
                networks.append({
                    'ssid': parts[0] if parts[0] else '(Hidden)',
                    'bssid': parts[1],
                    'signal': signal,
                    'security': parts[3] if parts[3] else 'Open',
                    'channel': parts[4],
                })
        return networks
    except Exception:
        pass

    # Fallback: iwlist
    try:
        interfaces = subprocess.check_output(['iwconfig'], encoding='utf-8', errors='ignore')
        iface = re.search(r'^(\w+)\s+IEEE', interfaces, re.MULTILINE)
        iface = iface.group(1) if iface else 'wlan0'

        result = subprocess.check_output(
            ['sudo', 'iwlist', iface, 'scan'],
            encoding='utf-8', errors='ignore'
        )

        cells = result.split('Cell ')
        for cell in cells[1:]:
            ssid_match = re.search(r'ESSID:"(.+?)"', cell)
            bssid_match = re.search(r'Address: ([0-9A-Fa-f:]+)', cell)
            signal_match = re.search(r'Signal level=(-?\d+)', cell)
            enc_match = re.search(r'Encryption key:(on|off)', cell)
            chan_match = re.search(r'Channel:(\d+)', cell)

            if ssid_match:
                sig_dbm = int(signal_match.group(1)) if signal_match else -100
                signal_pct = dbm_to_percent(sig_dbm)
                enc = enc_match.group(1) if enc_match else 'off'
                networks.append({
                    'ssid': ssid_match.group(1).strip() or '(Hidden)',
                    'bssid': bssid_match.group(1) if bssid_match else 'N/A',
                    'signal': signal_pct,
                    'security': 'WPA/WEP' if enc == 'on' else 'Open',
                    'channel': chan_match.group(1) if chan_match else 'N/A',
                })
    except Exception as e:
        print(f"[Error] Could not scan (try running with sudo): {e}")

    return networks


# ─────────────────────────────────────────────
# macOS
# ─────────────────────────────────────────────
def scan_macos():
    networks = []
    airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
    try:
        result = subprocess.check_output(
            [airport, '-s'],
            encoding='utf-8', errors='ignore'
        )
        lines = result.strip().split('\n')
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 7:
                try:
                    rssi = int(parts[-6])
                    signal_pct = dbm_to_percent(rssi)
                except (ValueError, IndexError):
                    signal_pct = 0
                networks.append({
                    'ssid': parts[0],
                    'bssid': parts[1] if len(parts) > 1 else 'N/A',
                    'signal': signal_pct,
                    'security': parts[-1],
                    'channel': parts[2] if len(parts) > 2 else 'N/A',
                })
    except Exception as e:
        print(f"[Error] Could not scan on macOS: {e}")

    return networks


# ─────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────
def display_networks(networks):
    clear()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("=" * 75)
    print(f"  📡  Wi-Fi Analyzer  |  {now}  |  Found: {len(networks)} networks")
    print("=" * 75)

    if not networks:
        print("\n  No networks found. Make sure Wi-Fi is enabled.")
        print("  On Linux, try running with: sudo python3 wifi_analyzer.py\n")
        return

    # Sort by signal strength
    networks.sort(key=lambda x: x['signal'], reverse=True)

    print(f"\n  {'#':<4} {'SSID':<28} {'BSSID':<20} {'CH':<5} {'Signal':<14} {'Security':<20} {'Quality'}")
    print("  " + "-" * 100)

    for i, net in enumerate(networks, 1):
        ssid = net['ssid'][:27]
        bssid = net['bssid'][:19]
        channel = str(net['channel'])[:4]
        signal = net['signal']
        bar = signal_to_bar(signal)
        quality = signal_quality(signal)
        security = net['security'][:19]

        print(f"  {i:<4} {ssid:<28} {bssid:<20} {channel:<5} {bar} {signal:>3}%  {security:<20} {quality}")

    print("\n" + "=" * 75)
    print("  Signal: 0-39% 🔴 Poor  |  40-59% 🟠 Fair  |  60-79% 🟡 Good  |  80%+ 🟢 Excellent")
    print("=" * 75 + "\n")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
def main():
    system = platform.system()
    print(f"\n🔍 Scanning for Wi-Fi networks on {system}...\n")

    if system == 'Windows':
        networks = scan_windows()
    elif system == 'Linux':
        networks = scan_linux()
    elif system == 'Darwin':
        networks = scan_macos()
    else:
        print(f"Unsupported OS: {system}")
        return

    display_networks(networks)

    while True:
        choice = input("  Press [R] to refresh, [Q] to quit: ").strip().lower()
        if choice == 'r':
            print("\n🔍 Rescanning...\n")
            if system == 'Windows':
                networks = scan_windows()
            elif system == 'Linux':
                networks = scan_linux()
            elif system == 'Darwin':
                networks = scan_macos()
            display_networks(networks)
        elif choice == 'q':
            print("\n  Goodbye! 👋\n")
            break


if __name__ == '__main__':
    main()
