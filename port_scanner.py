"""TCP connect scanner for explicitly authorized targets."""

import socket
import time
import ipaddress

PORTS = [21, 22, 80, 443, 8080]
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def scan_ports(target="127.0.0.1", ports=None, timeout=1.0):
    """Check TCP connectivity. Returns a list of open ports."""
    ports = ports or PORTS

    # Resolve hostnames, then scan the resolved address.
    try:
        resolved_ip = socket.gethostbyname(target)
        ipaddress.ip_address(resolved_ip)
    except (socket.gaierror, ValueError):
        print(f"{RED}[!] Invalid or unresolvable target: {target}{RESET}")
        return []

    print(f"{GREEN}[+] TCP scan started for {target} ({resolved_ip}){RESET}")
    open_ports = []

    for port in ports:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            print(f"{YELLOW}[!] Skipping invalid port: {port}{RESET}")
            continue

        print(f"{YELLOW}[*] Checking TCP/{port}...{RESET}")
        time.sleep(0.15)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((resolved_ip, port))
            if result == 0:
                print(f"{GREEN}[+] Port {port} is OPEN{RESET}")
                open_ports.append(port)
            else:
                print(f"{RED}[-] Port {port} is closed or filtered{RESET}")
        except OSError as exc:
            print(f"{RED}[!] Error on port {port}: {exc}{RESET}")

    print(f"{GREEN}[+] Scan complete. Open ports: {open_ports}{RESET}")
    return open_ports
