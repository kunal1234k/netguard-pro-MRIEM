"""Windows Defender Firewall integration using the built-in netsh utility."""

import ipaddress
import platform
import subprocess
from dataclasses import dataclass

RULE_PREFIX = "NetGuardPro_Block_"


@dataclass
class FirewallResult:
    success: bool
    message: str


def _validate_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        raise ValueError("Please enter a valid IPv4 or IPv6 address.")


def _run_netsh(arguments):
    if platform.system() != "Windows":
        return FirewallResult(False, "This firewall module currently supports Windows only.")
    try:
        completed = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + arguments,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return FirewallResult(False, f"Could not execute netsh: {exc}")

    if completed.returncode == 0:
        return FirewallResult(True, (completed.stdout or "Windows Firewall command completed.").strip())
    detail = (completed.stderr or completed.stdout or "Unknown netsh error").strip()
    return FirewallResult(False, detail)


def block_ip(ip):
    """Create an inbound Windows Firewall block rule for a single IP."""
    try:
        clean_ip = _validate_ip(ip)
    except ValueError as exc:
        return FirewallResult(False, str(exc))

    rule_name = RULE_PREFIX + clean_ip.replace(":", "_").replace(".", "_")
    return _run_netsh([
        "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={clean_ip}",
        "enable=yes",
        "profile=any",
        "description=Created by NetGuard Pro",
    ])


def unblock_ip(ip):
    """Delete only the matching rule created by NetGuard Pro."""
    try:
        clean_ip = _validate_ip(ip)
    except ValueError as exc:
        return FirewallResult(False, str(exc))

    rule_name = RULE_PREFIX + clean_ip.replace(":", "_").replace(".", "_")
    return _run_netsh(["delete", "rule", f"name={rule_name}"])


def list_managed_rules():
    """Return NetGuard-managed firewall rule names, if netsh can query them."""
    result = _run_netsh(["show", "rule", "name=all"])
    if not result.success:
        return [f"Unable to query firewall rules: {result.message}"]

    return [
        line.strip()
        for line in result.message.splitlines()
        if RULE_PREFIX.lower() in line.lower()
    ]
