"""
NetGuard Pro - Advanced Network Security System
Project by: Kunal Bhardwaj (BCA 1st Year)
Teacher Name: Monika mam
MATU RAM INSTITUTE OF ENGINEERING & MANAGEMENT, ROHTAK
"""

import os
import sys
import time
import threading
from datetime import datetime

from port_scanner import scan_ports
from firewall import block_ip, unblock_ip, list_managed_rules
from bot_detection import TrafficMonitor

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(GREEN + r"""
 _   _ _____ _____ ____  _   _   _   _   ___ _____
| \ | | ____|_   _/ ___|| | | | | \ | | / _ \ ____|
|  \| |  _|   | | \___ \| |_| | |  \| || | | |  _|
| |\  | |___  | |  ___) |  _  | | |\  || |_| | |___
|_| \_|_____| |_| |____/|_| |_| |_| \_| \___/|_____|

          ADVANCED NETWORK SECURITY SYSTEM
""" + RESET)
    print(CYAN + "=" * 68 + RESET)
    print(f"{GREEN}Project by       : Kunal Bhardwaj (BCA 1st Year){RESET}")
    print(f"{GREEN}Teacher Name     : Monika mam{RESET}")
    print(f"{GREEN}Institution      : MATU RAM INSTITUTE OF ENGINEERING & MANAGEMENT, ROHTAK{RESET}")
    print(f"{GREEN}Project          : NetGuard Pro{RESET}")
    print(f"{GREEN}Started          : {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}{RESET}")
    print(CYAN + "=" * 68 + RESET)
    print(YELLOW + "Use only on systems and networks you own or are authorized to test." + RESET)
    print()


def pause():
    input(f"\n{CYAN}Press Enter to continue...{RESET}")


def main():
    banner()

    # The traffic monitor runs continuously in a background thread.
    # Port scanning is initiated on demand so the tool does not repeatedly
    # probe a network without the operator's knowledge.
    monitor = TrafficMonitor(log_dir=LOG_DIR, poll_interval=1.0)
    monitor.start()

    try:
        while True:
            print(GREEN + "\n============== NETGUARD PRO CONTROL PANEL ==============" + RESET)
            print("[1] Scan TCP ports (authorized target)")
            print("[2] Block an IP using Windows Firewall")
            print("[3] Remove a NetGuard-managed firewall block")
            print("[4] List NetGuard-managed firewall rules")
            print("[5] Show traffic-monitor status")
            print("[0] Exit")
            choice = input("\nSelect option: ").strip()

            if choice == "1":
                target = input("Target IP/hostname (default 127.0.0.1): ").strip() or "127.0.0.1"
                scan_ports(target)
                pause()

            elif choice == "2":
                ip = input("IP address to block: ").strip()
                result = block_ip(ip)
                print((GREEN if result else RED) + result.message + RESET)
                pause()

            elif choice == "3":
                ip = input("IP address to unblock: ").strip()
                result = unblock_ip(ip)
                print((GREEN if result else RED) + result.message + RESET)
                pause()

            elif choice == "4":
                rules = list_managed_rules()
                if rules:
                    for rule in rules:
                        print(GREEN + f" - {rule}" + RESET)
                else:
                    print(YELLOW + "No NetGuard-managed block rules found." + RESET)
                pause()

            elif choice == "5":
                print(monitor.status())
                pause()

            elif choice == "0":
                print(YELLOW + "Stopping background traffic monitor..." + RESET)
                break

            else:
                print(RED + "Invalid option." + RESET)
                time.sleep(0.7)

    except KeyboardInterrupt:
        print("\n" + YELLOW + "Shutdown requested." + RESET)
    finally:
        monitor.stop()
        monitor.join(timeout=3)
        print(GREEN + "NetGuard Pro stopped." + RESET)


if __name__ == "__main__":
    main()
