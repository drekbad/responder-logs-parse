#!/usr/bin/env python3
"""
Summarize poisoned clients from Responder logs, by IP.

Default output (one line per client IP):
  IP,HOSTNAME,PROTO1|PROTO2|...

HOSTNAME comes from --resolve mode:
  - none  : leave blank
  - rdns  : reverse DNS via socket.gethostbyaddr()
  - infer : infer from names that client queried (e.g., collapse 'B3-5052ci-112' -> 'B3-5052ci'
            ONLY if base also appears among that IP's names; ignore NBNS Local Master Browser noise)
  - merge : rdns first; if empty, fallback to infer

Usage examples:
  python3 poisoned_clients.py
  python3 poisoned_clients.py --resolve rdns
  python3 poisoned_clients.py --resolve merge -d /usr/share/responder/logs > poisoned.csv
"""

import argparse, os, re, ipaddress, socket
from collections import defaultdict, Counter
from typing import Optional, Iterable, Set

DEFAULT_LOGDIR = "/usr/share/responder/logs"
LOG_FILES = ("Analyzer-Session.log", "Poisoners-Session.log", "Responder-Session.log")

# Match lines like:
#   [*] [LLMNR] Poisoned answer sent to 172.16.1.5 for name B3-5052ci-112
#   [*] [NBT-NS] Poisoned response sent to 172.16.1.2 for name SOME-DOMAIN (service: Local Master Browser)
LINE_RX = re.compile(
    r"Poisoned\s+(?:answer|response)\s+sent\s+to\s+(?P<ip>\S+)"
    r".*?for\s+(?:name|workstation)\s+(?P<name>[A-Za-z0-9_.:-]+)"
    r"(?:\s*\(service:\s*(?P<service>[^)]+)\))?",
    re.IGNORECASE,
)

# Pull protocol tokens from the same line
PROTO_RX = re.compile(r"\b(LLMNR|WPAD|MDNS|NBNS|NETBIOS-NS|NBT-NS)\b", re.IGNORECASE)

def normalize_proto(tok: str) -> str:
    t = tok.upper()
    if t in ("NBNS", "NETBIOS-NS"): return "NBT-NS"
    if t in ("LLMNR", "WPAD", "MDNS", "NBT-NS"): return t
    return "UNKNOWN"

def clean_ip(ip_raw: str) -> str:
    # strip IPv6 zone id (e.g., fe80::1%eth0)
    return ip_raw.split("%", 1)[0]

def ip_version(ip_s: str) -> Optional[int]:
    try:
        return ipaddress.ip_address(ip_s).version
    except ValueError:
        return None

# --- Heuristic inference of a hostname from names an IP queried ---
SUFFIX_RX = re.compile(r"^(?P<base>[A-Za-z0-9_.:-]+?)-(?P<num>\d{1,5})$", re.ASCII)

def infer_hostname(cand_names: Iterable[str], noisy_services: Iterable[str]) -> str:
    """
    Try to pick a plausible hostname from names this client asked for.
    Rules:
      - ignore NBNS Local Master Browser noise
      - detect suffix pattern '<base>-<digits>' but only collapse to <base> if <base> itself appears
      - prefer the most frequent base/name
    """
    names = []
    lmb_noise = set(s for s in noisy_services if "local master browser" in s.lower())
    # We only use 'service' to exclude obvious NBNS role noise; 'name' field itself is kept.
    for n in cand_names:
        if n.upper() in ("WPAD",):  # not a hostname
            continue
        names.append(n)

    if not names:
        return ""

    # Count occurrences
    counts = Counter(names)

    # Build set of bases that also appear as standalone names
    bases_present: Set[str] = set()
    for n in counts:
        m = SUFFIX_RX.match(n)
        if m:
            base = m.group("base")
            if base in counts:
                bases_present.add(base)

    # Build a candidate score list (name or base)
    scored = Counter()
    for n, c in counts.items():
        m = SUFFIX_RX.match(n)
        if m:
            base = m.group("base")
            # Only collapse if the base also appears as its own name
            if base in bases_present:
                scored[base] += c
            else:
                scored[n] += c
        else:
            scored[n] += c

    # Pick the most common candidate (ties broken by shorter, then lexical)
    best = sorted(scored.items(), key=lambda kv: (-kv[1], len(kv[0]), kv[0]))[0][0]
    return best

def resolve_rdns(ip_s: str, timeout: float = 2.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip_s)
        return name
    except Exception:
        return ""

def main():
    ap = argparse.ArgumentParser(description="Summarize poisoned clients by IP from Responder logs.")
    ap.add_argument("-d", "--logdir", default=DEFAULT_LOGDIR, help="Logs directory.")
    ap.add_argument("--resolve", choices=["none","rdns","infer","merge"], default="none",
                    help="How to fill HOSTNAME column (default: none).")
    ap.add_argument("--header", action="store_true", help="Print CSV header row.")
    ap.add_argument("--suppress-mdns-local", action="store_true",
                    help="Ignore mDNS names ending in .local during inference (does not affect protocol list).")
    args = ap.parse_args()

    # client_ip -> data
    clients = defaultdict(lambda: {
        "version": None,
        "protos": set(),
        "names": set(),     # names this IP asked for (for optional inference)
        "services": set(),  # NBNS service notes like Local Master Browser
        "events": 0,
    })

    for fname in LOG_FILES:
        path = os.path.join(args.logdir, fname)
        if not os.path.isfile(path):
            continue
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                m = LINE_RX.search(line)
                if not m:
                    continue

                ip_s = clean_ip(m.group("ip"))
                name = (m.group("name") or "").rstrip(".,;:]")
                service = (m.group("service") or "").strip()

                found = {normalize_proto(p) for p in PROTO_RX.findall(line)}
                if not found:
                    found = {"UNKNOWN"}

                c = clients[ip_s]
                c["version"] = c["version"] or ip_version(ip_s)
                c["protos"].update(found)
                c["events"] += 1

                # Keep names for optional inference
                if args.suppress_mdns_local and name.lower().endswith(".local"):
                    pass
                else:
                    c["names"].add(name)
                if service:
                    c["services"].add(service)

    # Output
    if args.header:
        print("IP,HOSTNAME,PROTOS")

    for ip_s in sorted(clients.keys(), key=lambda s: (ip_version(s) or 9, s)):
        c = clients[ip_s]
        protos = "|".join(sorted(p for p in c["protos"] if p != "UNKNOWN")) or "UNKNOWN"

        hostname = ""
        if args.resolve == "rdns":
            hostname = resolve_rdns(ip_s)
        elif args.resolve == "infer":
            hostname = infer_hostname(c["names"], c["services"])
        elif args.resolve == "merge":
            hostname = resolve_rdns(ip_s) or infer_hostname(c["names"], c["services"])

        print(f"{ip_s},{hostname},{protos}")

if __name__ == "__main__":
    main()
