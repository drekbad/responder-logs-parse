#!/usr/bin/env python3
"""
Responder poisoned client summarizer (domain-aware).

One row per poisoned client IP:
  IP,LOG_NAME,RESOLVED_NAME,PROTOS

LOG_NAME is chosen ONLY from the logs; RESOLVED_NAME is optional rDNS.
If LOG_NAME is just a domain (e.g., some-domain.local), it is blanked.
If RESOLVED_NAME is host.domain and LOG_NAME is just that domain (or its mapped NetBIOS),
LOG_NAME is blanked as well.
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
    parts = name.split(".")
    return len(parts) == 2 and parts[1].lower() == "local"

def parse_netbios_pairs(pairs: Iterable[str]) -> Dict[str, str]:
    out = {}
    for p in pairs:
        if "=" in p:
            left, right = p.split("=", 1)
            if left and right:
                out[left.strip().upper()] = right.strip().lower()
    return out

def pick_log_name(
    names: Counter,
    services: Set[str],
    protos: Set[str],
    known_domains: Set[str],
    known_netbios: Dict[str, str],
) -> str:
    """
    Choose a representative LOG_NAME from what the IP asked for in the logs.
    Priority:
      1) FQDN ending in a known domain
      2) Other multi-label FQDNs (not single-label mDNS 'host.local')
      3) Shortname that ALSO has an FQDN variant among names
      4) Plain shortname
      5) Single-label mDNS 'host.local'
    Excludes: WPAD, bare NetBIOS domain labels, and names that are exactly a known DNS domain.
    """
    counts = Counter()
    lower_known_domains = {d.lower() for d in known_domains}

    for n, c in names.items():
        u = n.upper()
        nlow = n.lower()
        if u == "WPAD":
            continue
        if u in known_netbios:  # bare NetBIOS domain label
            continue
        if nlow in lower_known_domains:  # exactly a known DNS domain (not a host)
            continue
        counts[n] += c

    if not counts:
        return ""

    fqdn_known, fqdn_other, short, mdns_single = [], [], [], []
    short_to_fqdn = defaultdict(set)

    # classify
    for n in counts:
        nlow = n.lower()
        if "." in n:
            if any(nlow.endswith("." + d) or nlow == d for d in lower_known_domains):
                fqdn_known.append(n)
            elif not is_single_label_mdns(n):
                fqdn_other.append(n)
        else:
            short.append(n)

    # map short -> fqdn
    for f in fqdn_known + fqdn_other:
        s = f.split(".", 1)[0]
        short_to_fqdn[s].add(f)

    # candidate list by priority
    candidates = []
    candidates.extend(("fqdn_known", n) for n in fqdn_known)
    candidates.extend(("fqdn_other", n) for n in fqdn_other)
    for s in short:
        if s in short_to_fqdn:
            candidates.append(("short_with_fqdn", s))
    for s in short:
        if s not in short_to_fqdn:
            candidates.append(("short", s))
    for n in counts:
        if is_single_label_mdns(n):
            mdns_single.append(n)
    candidates.extend(("mdns_single", n) for n in mdns_single)

    priority_rank = {"fqdn_known":0,"fqdn_other":1,"short_with_fqdn":2,"short":3,"mdns_single":4}
    def score(item: Tuple[str,str]):
        kind, n = item
        return (priority_rank[kind], -counts[n], len(n), n.lower())

    return min(candidates, key=score)[1]

def resolve_rdns(ip_s: str, timeout: float = 2.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip_s)
        return name
    except Exception:
        return ""

def main():
    ap = argparse.ArgumentParser(description="Summarize poisoned clients by IP from Responder logs (domain-aware).")
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

    clients = defaultdict(lambda: {
        "version": None,
        "protos": set(),
        "name_counts": Counter(),
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
                protos = {normalize_proto(p) for p in PROTO_RX.findall(line)} or {"UNKNOWN"}

                e = clients[ip_s]
                e["version"] = e["version"] or ip_version(ip_s)
                e["protos"].update(protos)
                e["events"] += 1
                if name:
                    e["name_counts"][name] += 1
                if service:
                    e["services"].add(service)

    if args.header:
        print("IP,LOG_NAME,RESOLVED_NAME,PROTOS")

    for ip_s in sorted(clients.keys(), key=lambda s: (ip_version(s) or 9, s)):
        e = clients[ip_s]
        log_name = pick_log_name(e["name_counts"], e["services"], e["protos"], known_domains, known_netbios)
        resolved = resolve_rdns(ip_s) if args.resolve == "rdns" else ""

        # --- Domain-aware cleanup of LOG_NAME ---
        # 1) If LOG_NAME is exactly a known DNS domain -> blank it.
        if log_name and log_name.lower() in known_domains:
            log_name = ""

        # 2) If RESOLVED_NAME is FQDN host.domain and LOG_NAME equals domain (or mapped NetBIOS) -> blank it.
        if resolved and "." in resolved and log_name:
            resolved_domain = resolved.split(".", 1)[1].lower()
            if (log_name.lower() == resolved_domain) or (
                log_name.upper() in known_netbios and known_netbios[log_name.upper()].lower() == resolved_domain
            ):
                log_name = ""

        protos_out = "|".join(sorted(p for p in e["protos"] if p != "UNKNOWN")) or "UNKNOWN"
        print(f"{ip_s},{log_name},{resolved},{protos_out}")

if __name__ == "__main__":
    main()
