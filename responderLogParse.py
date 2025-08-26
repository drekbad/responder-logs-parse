#!/usr/bin/env python3
"""
Summarize successfully poisoned hosts from Responder logs.

Default output (one line per host):
  IP,HOSTNAME,PROTO1|PROTO2|...

Use --both-ips to output:
  IPv4,IPv6,HOSTNAME,PROTO1|PROTO2|...

By default, looks in /usr/share/responder/logs and scans:
  Analyzer-Session.log, Poisoners-Session.log, Responder-Session.log
"""

import argparse
import ipaddress
import os
import re
from typing import Optional

DEFAULT_LOGDIR = "/usr/share/responder/logs"
LOG_FILES = ("Analyzer-Session.log", "Poisoners-Session.log", "Responder-Session.log")

# Match the core event lines, e.g.:
#   "[timestamp] Poisoned response sent to 10.0.0.5 for name HOST123"
#   "[timestamp] Poisoned answer sent to fe80::1%wlan0 for workstation HOST123.domain.tld"
LINE_RX = re.compile(
    r"Poisoned\s+(?:answer|response)\s+sent\s+to\s+(?P<ip>\S+)"
    r".*?for\s+(?:name|workstation)\s+(?P<host>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)

# Pull protocol tokens from the same line (case-insensitive)
PROTO_RX = re.compile(r"\b(LLMNR|WPAD|MDNS|NBNS|NETBIOS-NS|NBT-NS)\b", re.IGNORECASE)

def normalize_proto(token: str) -> str:
    """Collapse minor variants/aliases to canonical names."""
    t = token.upper()
    # Map NBNS and NETBIOS-NS to NBT-NS
    if t in ("NBNS", "NETBIOS-NS"):
        return "NBT-NS"
    if t in ("LLMNR", "WPAD", "MDNS", "NBT-NS"):
        return t
    return "UNKNOWN"

def parse_ip(ip_raw: str) -> Optional[ipaddress._BaseAddress]:
    """Return ipaddress object (v4 or v6) or None. Strip IPv6 zone id (e.g., %eth0)."""
    ip_clean = ip_raw.split("%", 1)[0]
    try:
        return ipaddress.ip_address(ip_clean)
    except ValueError:
        return None

def main():
    ap = argparse.ArgumentParser(description="Summarize Responder 'poisoned' hosts.")
    ap.add_argument(
        "-d", "--logdir", default=DEFAULT_LOGDIR,
        help=f"Directory containing Responder logs (default: {DEFAULT_LOGDIR})",
    )
    ap.add_argument(
        "--both-ips", action="store_true",
        help="Output IPv4 and IPv6 as separate columns (IPv4,IPv6,HOSTNAME,PROTOS).",
    )
    ap.add_argument(
        "--sort", choices=["host", "ip"], default="host",
        help="Sort by hostname or preferred IP (default: host).",
    )
    args = ap.parse_args()

    # key: hostname lower → entry dict
    hosts = {}  # { key: {"name": str, "ipv4": str|None, "ipv6": str|None, "protos": set()} }

    for fname in LOG_FILES:
        path = os.path.join(args.logdir, fname)
        if not os.path.isfile(path):
            continue
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                m = LINE_RX.search(line)
                if not m:
                    continue

                ip_raw = m.group("ip")
                host = m.group("host").rstrip(".,;:]")  # trim common trailing punct
                key = host.lower()

                entry = hosts.setdefault(
                    key, {"name": host, "ipv4": None, "ipv6": None, "protos": set()}
                )

                # Collect any protocol tokens on the line
                for tok in set(PROTO_RX.findall(line)):
                    entry["protos"].add(normalize_proto(tok))

                # Record the first seen IPv4/IPv6 for the host
                ip_obj = parse_ip(ip_raw)
                if ip_obj:
                    if ip_obj.version == 4 and not entry["ipv4"]:
                        entry["ipv4"] = str(ip_obj)
                    elif ip_obj.version == 6 and not entry["ipv6"]:
                        entry["ipv6"] = str(ip_obj)

    # Prepare sorted keys
    if args.sort == "ip":
        def ip_sort_key(e):
            # Prefer IPv4; then IPv6; None sorts last
            v4 = hosts[e]["ipv4"]
            v6 = hosts[e]["ipv6"]
            ip_for_sort = v4 or v6 or "255.255.255.255"
            # best-effort numeric sort if possible
            try:
                return (0, ipaddress.ip_address(ip_for_sort))
            except ValueError:
                return (1, ip_for_sort)
        keys = sorted(hosts.keys(), key=ip_sort_key)
    else:
        keys = sorted(hosts.keys())

    # Output
    for k in keys:
        e = hosts[k]
        protos = "|".join(sorted(p for p in e["protos"] if p != "UNKNOWN")) or "UNKNOWN"
        if args.both_ips:
            print(f"{e['ipv4'] or ''},{e['ipv6'] or ''},{e['name']},{protos}")
        else:
            ip_out = e["ipv4"] or e["ipv6"] or "UNKNOWN"
            print(f"{ip_out},{e['name']},{protos}")

if __name__ == "__main__":
    main()
