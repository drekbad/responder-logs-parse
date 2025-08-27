#!/usr/bin/env python3
"""
Responder poisoned client summarizer (domain-aware + ban-names + multi-resolver).

One row per poisoned client IP:
  IP,LOG_NAME,RESOLVED_NAME,PROTOS[,FLAGS]

LOG_NAME is chosen ONLY from the logs; RESOLVED_NAME is optional (via a resolver chain).
LOG_NAME is blanked if it is just a domain, a banned name, or a NetBIOS label mapped to the resolved domain.
"""

import argparse, os, re, ipaddress, socket, subprocess
from collections import defaultdict, Counter
from typing import Optional, Dict, Iterable, Tuple, Set, List

DEFAULT_LOGDIR = "/usr/share/responder/logs"
LOG_FILES = ("Analyzer-Session.log", "Poisoners-Session.log", "Responder-Session.log")

LINE_RX = re.compile(
    r"Poisoned\s+(?:answer|response)\s+sent\s+to\s+(?P<ip>\S+)"
    r".*?for\s+(?:name|workstation)\s+(?P<name>[A-Za-z0-9_.:-]+)"
    r"(?:\s*\(service:\s*(?P<service>[^)]+)\))?",
    re.IGNORECASE,
)
PROTO_RX = re.compile(r"\b(LLMNR|WPAD|MDNS|NBNS|NETBIOS-NS|NBT-NS)\b", re.IGNORECASE)

DEFAULT_BANNED = {"wpad.local", "https.local"}  # exact matches (case-insensitive)

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

def parse_netbios_map(pairs: Iterable[str]) -> Dict[str, str]:
    """Parse NETBIOS=DNS form into {NETBIOS: dns.domain}"""
    out: Dict[str, str] = {}
    for p in pairs:
        if "=" in p:
            left, right = p.split("=", 1)
            nb = left.strip().upper()
            dns = right.strip().lower()
            if nb and dns:
                out[nb] = dns
    return out

def parse_domains_and_netbios(domain_flags: List[str], netbios_flags: List[str]) -> Tuple[Set[str], Dict[str,str], Set[str]]:
    """
    Accept:
      --domain some-domain.local
      --domain some-domain.local=SOME-DOMAIN   (DNS=NETBIOS)
      --netbios SOME-DOMAIN=some-domain.local
      --netbios SOME-DOMAIN                    (bare; auto-map if exactly one domain, else treated as 'bare NB only')
    Returns (known_domains, known_netbios_map, bare_netbios_set)
    """
    known_domains: Set[str] = set()
    known_netbios: Dict[str,str] = {}

    # Domains may be given as DNS or DNS=NETBIOS
    for d in domain_flags:
        if "=" in d:
            dns, nb = d.split("=", 1)
            dns = dns.strip().lower()
            nb  = nb.strip().upper()
            if dns:
                known_domains.add(dns)
            if dns and nb:
                known_netbios[nb] = dns
        else:
            dns = d.strip().lower()
            if dns:
                known_domains.add(dns)

    # NetBIOS flags: NETBIOS=DNS or bare NETBIOS
    explicit_map = parse_netbios_map([n for n in netbios_flags if "=" in n])
    known_netbios.update(explicit_map)
    bare_nb = {n.strip().upper() for n in netbios_flags if "=" not in n and n.strip()}

    # If exactly one domain is known, auto-map any bare NETBIOS labels to it
    if bare_nb and len(known_domains) == 1:
        only_dom = next(iter(known_domains))
        for nb in bare_nb:
            known_netbios[nb] = only_dom

    return known_domains, known_netbios, bare_nb

def pick_log_name(
    names: Counter,
    services: Set[str],
    protos: Set[str],
    known_domains: Set[str],
    known_netbios: Dict[str, str],
    banned_names: Set[str],
) -> Tuple[str, Set[str]]:
    """
    Choose a representative LOG_NAME from log-observed names for this IP.
    Excludes: WPAD, banned names (exact), bare NetBIOS labels, and names that equal a known DNS domain.
    Priority:
      1) FQDN ending in a known domain
      2) Other multi-label FQDNs (not 'host.local')
      3) Shortname that ALSO has an FQDN variant among names
      4) Plain shortname
      5) Single-label mDNS 'host.local'
    """
    flags = set()
    counts = Counter()
    lower_known_domains = {d.lower() for d in known_domains}
    banned_lower = {b.lower() for b in banned_names}

    for n, c in names.items():
        u = n.upper(); nlow = n.lower()
        if u == "WPAD":
            continue
        if nlow in banned_lower:
            flags.add("BANNED_LOGNAME_SEEN")
            continue
        if u in known_netbios:              # bare NetBIOS domain label
            continue
        if nlow in lower_known_domains:     # equals a known DNS domain
            flags.add("DOMAIN_ONLY_NAME_SEEN")
            continue
        counts[n] += c

    if not counts:
        return ("", flags)

    fqdn_known, fqdn_other, short, mdns_single = [], [], [], []
    short_to_fqdn = defaultdict(set)

    for n in counts:
        nlow = n.lower()
        if "." in n:
            if any(nlow.endswith("." + d) or nlow == d for d in lower_known_domains):
                fqdn_known.append(n)
            elif not is_single_label_mdns(n):
                fqdn_other.append(n)
        else:
            short.append(n)

    for f in fqdn_known + fqdn_other:
        s = f.split(".", 1)[0]
        short_to_fqdn[s].add(f)

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

    return (min(candidates, key=score)[1], flags)

# ---------- resolvers ----------
def resolve_rdns(ip_s: str, timeout: float = 1.5) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip_s)
        return name.rstrip(".")
    except Exception:
        return ""

def run_cmd(cmd: List[str], timeout: float = 2.5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return (r.stdout or "").strip()
        return ""
    except Exception:
        return ""

def resolve_dns_tools(ip_s: str, dns_servers: List[str]) -> str:
    cmds = []
    if dns_servers:
        for s in dns_servers:
            cmds.append(["dig", "+short", "-x", ip_s, "@"+s, "+time=1", "+tries=1"])
        for s in dns_servers:
            cmds.append(["host", "-W", "1", ip_s, s])
    else:
        cmds.append(["dig", "+short", "-x", ip_s, "+time=1", "+tries=1"])
        cmds.append(["host", "-W", "1", ip_s])

    for c in cmds:
        out = run_cmd(c)
        if not out:
            continue
        line = out.splitlines()[0].strip()
        if not line:
            continue
        if "pointer" in line:
            return line.split()[-1].rstrip(".")
        if "." in line:
            return line.rstrip(".")
    return ""

def resolve_getent(ip_s: str) -> str:
    out = run_cmd(["getent", "hosts", ip_s])
    if out:
        parts = out.split()
        if len(parts) >= 2:
            return parts[1].rstrip(".")
    return ""

def tcp_port_open(ip_s: str, port: int, timeout: float = 0.6) -> bool:
    try:
        fam = socket.AF_INET6 if ip_version(ip_s) == 6 else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip_s, port))
        return True
    except Exception:
        return False

NXC_NAME_RX = re.compile(r"\(name:([A-Za-z0-9_.-]+)\)")
NXC_DOM_RX  = re.compile(r"\(domain:([A-Za-z0-9_.-]+)\)")

def resolve_nxc(ip_s: str, timeout: float = 4.0) -> str:
    if not tcp_port_open(ip_s, 445, timeout=min(0.8, timeout)):
        return ""
    out = run_cmd(["nxc", "smb", ip_s, "--timeout", str(int(max(1, timeout)))], timeout=timeout+1.0)
    if not out:
        return ""
    name = ""
    dom = ""
    m = NXC_NAME_RX.search(out)
    if m: name = m.group(1)
    m2 = NXC_DOM_RX.search(out)
    if m2: dom = m2.group(1)
    if name and dom and "." in dom and "." not in name:
        return f"{name}.{dom}".rstrip(".")
    return name or ""

def resolve_chain(ip_s: str, chain: List[str], dns_servers: List[str], nxc_timeout: float) -> str:
    for step in chain:
        if step == "rdns":
            r = resolve_rdns(ip_s)
        elif step == "dns":
            r = resolve_dns_tools(ip_s, dns_servers)
        elif step == "getent":
            r = resolve_getent(ip_s)
        elif step == "nxc":
            r = resolve_nxc(ip_s, timeout=nxc_timeout)
        else:
            r = ""
        if r:
            return r
    return ""

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Summarize poisoned clients by IP from Responder logs (domain-aware, resolvers, ban-names).")
    ap.add_argument("-d", "--logdir", default=DEFAULT_LOGDIR, help="Logs directory.")
    ap.add_argument("--header", action="store_true", help="Print CSV header row.")
    # domains / netbios
    ap.add_argument("--domain", action="append", default=[], help="DNS domain or DNS=NETBIOS (repeatable).")
    ap.add_argument("--netbios", action="append", default=[], help="NETBIOS=DNS or bare NETBIOS (repeatable).")
    # name banning
    ap.add_argument("--ban-name", action="append", default=[], help="Exact log name to ignore (repeatable).")
    ap.add_argument("--no-ban-defaults", action="store_true", help="Do not auto-ban wpad.local / https.local.")
    # resolvers
    ap.add_argument("--resolve-chain", default="rdns", help="Comma list from: rdns,dns,getent,nxc (order matters).")
    ap.add_argument("--dns", action="append", default=[], help="DNS server for 'dns' resolver (repeatable).")
    ap.add_argument("--nxc-timeout", type=float, default=4.0, help="Timeout seconds for nxc smb.")
    ap.add_argument("--flags", action="store_true", help="Include a FLAGS column with reasons/notes.")
    args = ap.parse_args()

    known_domains, known_netbios, bare_nb = parse_domains_and_netbios(args.domain, args.netbios)

    banned_names = set(n.strip() for n in args.ban_name if n.strip())
    if not args.no_ban_defaults:  # <-- fixed underscore attribute
        banned_names |= DEFAULT_BANNED

    chain = [t.strip().lower() for t in args.resolve_chain.split(",") if t.strip()]

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
        cols = ["IP","LOG_NAME","RESOLVED_NAME","PROTOS"]
        if args.flags:
            cols.append("FLAGS")
        print(",".join(cols))

    for ip_s in sorted(clients.keys(), key=lambda s: (ip_version(s) or 9, s)):
        e = clients[ip_s]
        flags = set()
        log_name, pick_flags = pick_log_name(e["name_counts"], e["services"], e["protos"], known_domains, known_netbios, banned_names)
        flags |= pick_flags

        resolved = resolve_chain(ip_s, chain, args.dns, args.nxc_timeout) if chain else ""
        protos_out = "|".join(sorted(p for p in e["protos"] if p != "UNKNOWN")) or "UNKNOWN"

        # domain-aware cleanup of LOG_NAME
        if log_name and log_name.lower() in known_domains:
            log_name = ""
            flags.add("BLANKED_DOMAIN_LOGNAME")
        if resolved and "." in resolved and log_name:
            resolved_domain = resolved.split(".", 1)[1].lower()
            if (log_name.lower() == resolved_domain) or (
                log_name.upper() in known_netbios and known_netbios[log_name.upper()].lower() == resolved_domain
            ):
                log_name = ""
                flags.add("BLANKED_DOMAIN_LOGNAME_BY_RESOLVED")

        row = [ip_s, log_name, resolved, protos_out]
        if args.flags:
            row.append("|".join(sorted(flags)))
        print(",".join(row))

if __name__ == "__main__":
    main()
