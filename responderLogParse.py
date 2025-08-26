#!/usr/bin/env python3
"""
Responder poisoned client summarizer.

One row per poisoned client IP:
  IP,LOG_NAME,RESOLVED_NAME,PROTOS

- LOG_NAME: chosen ONLY from what appears in the logs (never overwritten)
- RESOLVED_NAME: optional reverse DNS (rDNS), separate column
- PROTOS: e.g., LLMNR|NBT-NS|MDNS|WPAD

You can hint known domains and NetBIOS names:
  --domain some-domain.local                (repeatable)
  --netbios SOME-DOMAIN=some-domain.local  (repeatable)

Examples:
  python3 poisoned_clients_final.py
  python3 poisoned_clients_final.py --resolve rdns --domain some-domain.local --netbios SOME-DOMAIN=some-domain.local --header
"""

import argparse, os, re, ipaddress, socket
from collections import defaultdict, Counter
from typing import Optional, Dict, Iterable, Tuple, Set

DEFAULT_LOGDIR = "/usr/share/responder/logs"
LOG_FILES = ("Analyzer-Session.log", "Poisoners-Session.log", "Responder-Session.log")

LINE_RX = re.compile(
    r"Poisoned\s+(?:answer|response)\s+sent\s+to\s+(?P<ip>\S+)"
    r".*?for\s+(?:name|workstation)\s+(?P<name>[A-Za-z0-9_.:-]+)"
    r"(?:\s*\(service:\s*(?P<service>[^)]+)\))?",
    re.IGNORECASE,
)
PROTO_RX = re.compile(r"\b(LLMNR|WPAD|MDNS|NBNS|NETBIOS-NS|NBT-NS)\b", re.IGNORECASE)

def normalize_proto(tok: str) -> str:
    t = tok.upper()
    if t in ("NBNS", "NETBIOS-NS"): return "NBT-NS"
    if t in ("LLMNR", "WPAD", "MDNS", "NBT-NS"): return t
    return "UNKNOWN"

def clean_ip(ip_raw: str) -> str:
    return ip_raw.split("%", 1)[0]  # strip IPv6 zone id

def ip_version(ip_s: str) -> Optional[int]:
    try:
        return ipaddress.ip_address(ip_s).version
    except ValueError:
        return None

def is_single_label_mdns(name: str) -> bool:
    # e.g., "host.local" (one dot, 'local' TLD), common Bonjour pattern
    parts = name.split(".")
    return len(parts) == 2 and parts[1].lower() == "local"

def pick_log_name(
    names: Counter,
    services: Set[str],
    protos: Set[str],
    known_domains: Set[str],
    known_netbios: Dict[str, str],
) -> str:
    """
    Choose a representative LOG_NAME from what the IP asked for in the logs.
    Priority (highest first):
      1) FQDN that ends with a known domain (e.g., host.some-domain.local)
      2) Other multi-label FQDNs (not single-label mDNS 'host.local')
      3) Shortname that ALSO has a corresponding FQDN variant among names
      4) Plain shortname (no dots)
      5) Single-label mDNS 'host.local'
    Excludes obvious NBNS role noise and bare NetBIOS domain labels.
    """
    # Exclude NBNS role noise
    if any("local master browser" in s.lower() for s in services):
        # We can't remove specific events here, but we can avoid choosing the bare domain label.
        pass

    # Create working copy with counts
    counts = Counter()
    for n, c in names.items():
        u = n.upper()
        # Exclude literal WPAD and bare NetBIOS domain labels
        if u == "WPAD":
            continue
        if u in known_netbios:  # e.g., "SOME-DOMAIN" alone isn't a hostname
            continue
        counts[n] += c

    if not counts:
        return ""

    # Helper sets
    lower_known_domains = {d.lower() for d in known_domains}
    fqdn = []
    fqdn_known = []
    short = []
    mdns_single = []

    # Build maps to detect shortname <-> fqdn relationships
    # e.g., 'host' and 'host.some-domain.local'
    short_to_fqdn = defaultdict(set)
    for n in counts:
        if "." in n:
            if any(n.lower().endswith("." + d) or n.lower() == d for d in lower_known_domains):
                fqdn_known.append(n)
            elif not is_single_label_mdns(n):
                fqdn.append(n)
        else:
            short.append(n)

    # map short -> fqdn (prefix match before first dot)
    all_fqdns = fqdn_known + fqdn
    for f in all_fqdns:
        s = f.split(".", 1)[0]
        short_to_fqdn[s].add(f)

    # Build candidate lists by priority
    candidates = []
    if fqdn_known:
        candidates.extend(("fqdn_known", n) for n in fqdn_known)
    if fqdn:
        candidates.extend(("fqdn_other", n) for n in fqdn)
    # short names that have fqdn variants
    for s in short:
        if s in short_to_fqdn:
            candidates.append(("short_with_fqdn", s))
    # remaining short names
    for s in short:
        if s not in short_to_fqdn:
            candidates.append(("short", s))
    # finally, single-label mdns names (host.local)
    for n in counts:
        if is_single_label_mdns(n):
            mdns_single.append(n)
    candidates.extend(("mdns_single", n) for n in mdns_single)

    # Score + pick best (by priority, then by descending count, then shorter, then lexicographic)
    priority_rank = {
        "fqdn_known": 0,
        "fqdn_other": 1,
        "short_with_fqdn": 2,
        "short": 3,
        "mdns_single": 4,
    }
    def score(item: Tuple[str, str]):
        kind, n = item
        return (priority_rank[kind], -counts[n], len(n), n.lower())

    best = min(candidates, key=score)[1]
    return best

def resolve_rdns(ip_s: str, timeout: float = 2.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip_s)
        return name
    except Exception:
        return ""

def parse_netbios_pairs(pairs: Iterable[str]) -> Dict[str, str]:
    out = {}
    for p in pairs:
        if "=" in p:
            left, right = p.split("=", 1)
            if left and right:
                out[left.strip().upper()] = right.strip().lower()
    return out

def main():
    ap = argparse.ArgumentParser(description="Summarize poisoned clients by IP from Responder logs.")
    ap.add_argument("-d", "--logdir", default=DEFAULT_LOGDIR, help="Logs directory.")
    ap.add_argument("--resolve", choices=["none","rdns"], default="none",
                    help="Fill RESOLVED_NAME via rDNS (never overwrites LOG_NAME).")
    ap.add_argument("--domain", action="append", default=[],
                    help="Known AD DNS domain (repeatable), e.g. --domain some-domain.local")
    ap.add_argument("--netbios", action="append", default=[],
                    help="Map NetBIOS to DNS domain, e.g. --netbios SOME-DOMAIN=some-domain.local (repeatable)")
    ap.add_argument("--header", action="store_true", help="Print CSV header row.")
    args = ap.parse_args()

    known_domains = set([d.strip().lower() for d in args.domain if d.strip()])
    known_netbios = parse_netbios_pairs(args.netbios)

    # client_ip -> data
    clients = defaultdict(lambda: {
        "version": None,
        "protos": set(),
        "name_counts": Counter(),  # names seen from logs for this IP
        "services": set(),
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

                protos = {normalize_proto(p) for p in PROTO_RX.findall(line)}
                if not protos:
                    protos = {"UNKNOWN"}

                entry = clients[ip_s]
                entry["version"] = entry["version"] or ip_version(ip_s)
                entry["protos"].update(protos)
                entry["events"] += 1

                # Keep all raw names for this IP (we choose one later)
                if name:
                    entry["name_counts"][name] += 1
                if service:
                    entry["services"].add(service)

    if args.header:
        print("IP,LOG_NAME,RESOLVED_NAME,PROTOS")

    # Emit one row per IP
    for ip_s in sorted(clients.keys(), key=lambda s: (ip_version(s) or 9, s)):
        e = clients[ip_s]
        log_name = pick_log_name(
            e["name_counts"], e["services"], e["protos"], known_domains, known_netbios
        )
        resolved = resolve_rdns(ip_s) if args.resolve == "rdns" else ""
        protos = "|".join(sorted(p for p in e["protos"] if p != "UNKNOWN")) or "UNKNOWN"
        print(f"{ip_s},{log_name},{resolved},{protos}")

if __name__ == "__main__":
    main()
