#!/usr/bin/env python3
"""
Responder poisoned client summarizer (domain-aware, multi-resolver) with:
- Guided IPv6↔IPv4 merging (union-find)
- Log-name, DNS AAAA/A, synthesized FQDN, capture-name hints, and MAC neighbor linking
- Quiet by default (DNS-only unless you include getent/nxc)

Output (default):
  IP,LOG_NAME,RESOLVED_NAME,PROTOS[,FLAGS]
Or with --merge6:
  IPv4;IPv4...,IPv6;IPv6...,LOG_NAME,RESOLVED_NAME,PROTOS[,FLAGS]

Useful flags:
  --resolve --resolve-chain rdns,dns[,getent,nxc] --dns <dc> --dns <dc2>
  --merge6
  --domain some-domain.local[=SOMEDOMAIN]   (repeatable)
  --netbios SOMEDOMAIN[=some-domain.local]  (repeatable)
  --ban-name NAME                           (repeatable; exact match)
  --no-ban-defaults                         (don’t auto-ban wpad.local / https.local)
  --capture-names / --no-capture-names      (default: on)
  --mac-link                                 (use ARP/NDP to merge by MAC)
  --synth / --no-synth                       (default: on if any --domain given)
  --why-merge                                (explain merge reasons in FLAGS)
  --flags                                    (include FLAGS column)
"""

import argparse, os, re, ipaddress, socket, subprocess, sys
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

# Capture-name mining (Responder-Session.log)
CLIENT_RX = re.compile(r"(?i)\[(?:[A-Z0-9 -]+)\]\s+(?:NTLMv2\s+)?Client\s*:\s*(?P<ip>\S+)")
ALT_CLIENT_RX = re.compile(r"(?i)Hash\s+captured\s+from\s+(?P<ip>\S+)")
NAME_HINT_RX = re.compile(r"(?i)\b(?:HostName|Hostname|Workstation|Machine|Computer(?:Name)?)\s*[:=]\s*([A-Za-z0-9_.-]+)")

DEFAULT_BANNED = {"wpad.local", "https.local"}  # exact (case-insensitive)

# ---------- helpers ----------
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
    known_domains: Set[str] = set()
    known_netbios: Dict[str,str] = {}
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

    explicit_map = parse_netbios_map([n for n in netbios_flags if "=" in n])
    known_netbios.update(explicit_map)
    bare_nb = {n.strip().upper() for n in netbios_flags if "=" not in n and n.strip()}

    if bare_nb and len(known_domains) == 1:
        only_dom = next(iter(known_domains))
        for nb in bare_nb:
            known_netbios[nb] = only_dom

    return known_domains, known_netbios, bare_nb

def ip_sort_key_str(ip_str: str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return (0 if addr.version == 4 else 1, addr)
    except ValueError:
        return (2, ip_str)

def merged_row_sort_key(row: dict):
    v4s = [ipaddress.ip_address(x) for x in row["ipv4"].split(";") if x]
    v6s = [ipaddress.ip_address(x) for x in row["ipv6"].split(";") if x]
    if v4s:
        return (0, min(v4s))
    if v6s:
        return (1, min(v6s))
    return (2, row.get("resolved","") or row.get("log_name",""))

# ---------- resolvers ----------
def run_cmd(cmd: List[str], timeout: float = 2.5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return (r.stdout or "").strip()
        return ""
    except Exception:
        return ""

def resolve_rdns(ip_s: str, timeout: float = 1.5) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip_s)
        return name.rstrip(".")
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

def forward_lookup_A(name: str, dns_servers: List[str]) -> List[str]:
    addrs: List[str] = []
    if not name:
        return addrs
    cmds = []
    if dns_servers:
        for s in dns_servers:
            cmds.append(["dig", "+short", name, "A", "@"+s, "+time=1", "+tries=1"])
        for s in dns_servers:
            cmds.append(["getent", "hosts", name])
    else:
        cmds.append(["dig", "+short", name, "A", "+time=1", "+tries=1"])
        cmds.append(["getent", "hosts", name])
    for c in cmds:
        out = run_cmd(c)
        if not out:
            continue
        for line in out.splitlines():
            for t in line.strip().split():
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
                    addrs.append(t)
    return sorted(set(addrs))

def forward_lookup_AAAA(name: str, dns_servers: List[str]) -> List[str]:
    addrs: List[str] = []
    if not name:
        return addrs
    cmds = []
    if dns_servers:
        for s in dns_servers:
            cmds.append(["dig", "+short", name, "AAAA", "@"+s, "+time=1", "+tries=1"])
        for s in dns_servers:
            cmds.append(["getent", "ahosts", name])  # returns v4/v6; we'll filter
    else:
        cmds.append(["dig", "+short", name, "AAAA", "+time=1", "+tries=1"])
        cmds.append(["getent", "ahosts", name])
    for c in cmds:
        out = run_cmd(c)
        if not out:
            continue
        for line in out.splitlines():
            for tok in line.strip().split():
                try:
                    ip = ipaddress.ip_address(tok)
                    if ip.version == 6:
                        addrs.append(str(ip))
                except ValueError:
                    continue
    return sorted(set(addrs))

# ---------- tiny name helpers ----------
def split_host_domain(name: str) -> Tuple[str, str]:
    if not name:
        return ("","")
    n = name.strip(".")
    parts = n.split(".")
    if len(parts) < 2:
        return (n.lower(), "")
    return (parts[0].lower(), ".".join(parts[1:]).lower())

def best_name_pair(row: dict) -> Tuple[str, str, str]:
    cand = row.get("resolved") or row.get("log_name") or ""
    short, dom = split_host_domain(cand)
    if "." in cand:
        return (cand.lower(), short, dom)
    return ("", short, dom)

# ---------- neighbor tables (quiet) ----------
def load_arp_ipv4() -> Dict[str, str]:
    macs = {}
    try:
        with open("/proc/net/arp", "r") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    ip, mac = parts[0], parts[3]
                    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) and re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac, re.I):
                        macs[ip] = mac.lower()
    except Exception:
        pass
    return macs

def load_ndp_ipv6() -> Dict[str, str]:
    macs = {}
    out = run_cmd(["ip", "-6", "neigh", "show"], timeout=2.0)
    for line in (out or "").splitlines():
        # fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        m = re.search(r"^(\S+).*\blladdr\s+([0-9a-f:]{17})\b", line, re.I)
        if m:
            ip, mac = m.group(1), m.group(2).lower()
            try:
                if ipaddress.ip_address(ip).version == 6:
                    macs[clean_ip(ip)] = mac
            except ValueError:
                continue
    return macs

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Summarize poisoned clients by IP from Responder logs.")
    ap.add_argument("-d", "--logdir", default=DEFAULT_LOGDIR, help="Logs directory.")
    ap.add_argument("--header", action="store_true", help="Print CSV header row.")
    # domains / netbios
    ap.add_argument("--domain", action="append", default=[], help="DNS domain or DNS=NETBIOS (repeatable).")
    ap.add_argument("--netbios", action="append", default=[], help="NETBIOS=DNS or bare NETBIOS (repeatable).")
    # name banning
    ap.add_argument("--ban-name", action="append", default=[], help="Exact log name to ignore (repeatable).")
    ap.add_argument("--no-ban-defaults", action="store_true", help="Do not auto-ban wpad.local / https.local.")
    # resolvers
    ap.add_argument("--resolve", action="store_true", help="Run chain rdns,dns[,getent,nxc] (order via --resolve-chain).")
    ap.add_argument("--resolve-chain", default="rdns", help="Comma list: rdns,dns,getent,nxc")
    ap.add_argument("--dns", action="append", default=[], help="DNS server for A/AAAA/PTR lookups (repeatable).")
    ap.add_argument("--nxc-timeout", type=float, default=4.0, help="Timeout seconds for nxc smb.")
    # extras
    ap.add_argument("--capture-names", dest="capture_names", action="store_true", default=True, help="Mine HostName/Workstation from capture logs (default on).")
    ap.add_argument("--no-capture-names", dest="capture_names", action="store_false")
    ap.add_argument("--mac-link", action="store_true", help="Merge IPv4/IPv6 by MAC from neighbor tables (quiet).")
    ap.add_argument("--synth", dest="synth", action="store_true", help="Use short+domain synthesized FQDN for extra A/AAAA lookups.")
    ap.add_argument("--no-synth", dest="synth", action="store_false")
    # merge
    ap.add_argument("--merge6", "--merge-v4v6", dest="merge6", action="store_true",
                    help="Merge IPv6 rows into IPv4 rows when correlated by name/DNS/MAC.")
    ap.add_argument("--flags", action="store_true", help="Include a FLAGS column.")
    ap.add_argument("--why-merge", action="store_true", help="Annotate merge reasons in FLAGS.")
    args = ap.parse_args()

    known_domains, known_netbios, _ = parse_domains_and_netbios(args.domain, args.netbios)
    if args.synth is None:
        args.synth = bool(known_domains)  # enable synth if domains were provided
    banned_names = set(n.strip() for n in args.ban_name if n.strip())
    if not args.no_ban_defaults:
        banned_names |= DEFAULT_BANNED

    # Resolver chain
    chain = [t.strip().lower() for t in args.resolve_chain.split(",") if t.strip()]
    if args.resolve and args.resolve_chain == "rdns":
        chain = ["rdns", "dns", "getent", "nxc"]

    # Collect raw per-IP rows
    clients = defaultdict(lambda: {
        "version": None,
        "protos": set(),
        "name_counts": Counter(),
        "services": set(),
        "events": 0,
    })

    # Parse poisoned lines
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

    # OPTIONAL: harvest capture names from Responder-Session.log
    if args.capture_names:
        path = os.path.join(args.logdir, "Responder-Session.log")
        if os.path.isfile(path):
            last_ip = ""
            with open(path, "r", errors="ignore") as fh:
                for line in fh:
                    m = CLIENT_RX.search(line) or ALT_CLIENT_RX.search(line)
                    if m:
                        last_ip = clean_ip(m.group("ip"))
                        continue
                    if last_ip:
                        nm = NAME_HINT_RX.search(line)
                        if nm:
                            name = nm.group(1).rstrip(".,;:]")
                            if name:
                                e = clients[last_ip]
                                e["version"] = e["version"] or ip_version(last_ip)
                                e["name_counts"][name] += 1

    # Build per-IP rows
    rows = []
    def pick_log_name(names: Counter, services: Set[str], protos: Set[str],
                      known_domains: Set[str], known_netbios: Dict[str, str],
                      banned_names: Set[str]) -> Tuple[str, Set[str]]:
        flags = set()
        counts = Counter()
        lower_known_domains = {d.lower() for d in known_domains}
        banned_lower = {b.lower() for b in banned_names}

        for n, c in names.items():
            u = n.upper(); nlow = n.lower()
            if u == "WPAD":
                continue
            if nlow in banned_lower:
                flags.add("BANNED_LOGNAME_SEEN"); continue
            if u in known_netbios:
                continue
            if nlow in lower_known_domains:
                flags.add("DOMAIN_ONLY_NAME_SEEN"); continue
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
            s = f.split(".", 1)[0]; short_to_fqdn[s].add(f)

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

    for ip_s in sorted(clients.keys(), key=ip_sort_key_str):
        e = clients[ip_s]
        flags = set()
        log_name, pick_flags = pick_log_name(e["name_counts"], e["services"], e["protos"],
                                             known_domains, known_netbios, banned_names)
        flags |= pick_flags
        # resolution
        resolved = ""
        if chain:
            for step in chain:
                if step == "rdns":
                    resolved = resolve_rdns(ip_s)
                elif step == "dns":
                    resolved = resolve_dns_tools(ip_s, args.dns)
                elif step == "getent":
                    resolved = resolve_getent(ip_s)
                elif step == "nxc":
                    resolved = resolve_nxc(ip_s, timeout=args.nxc_timeout)
                if resolved:
                    break

        if log_name and log_name.lower() in known_domains:
            log_name = ""; flags.add("BLANKED_DOMAIN_LOGNAME")
        if resolved and "." in resolved and log_name:
            resolved_domain = resolved.split(".", 1)[1].lower()
            if (log_name.lower() == resolved_domain) or (
                log_name.upper() in known_netbios and known_netbios[log_name.upper()].lower() == resolved_domain
            ):
                log_name = ""; flags.add("BLANKED_DOMAIN_LOGNAME_BY_RESOLVED")

        rows.append({
            "ip": ip_s,
            "v": e["version"],
            "log_name": log_name,
            "resolved": resolved,
            "protos": set(p for p in e["protos"] if p != "UNKNOWN") or {"UNKNOWN"},
            "flags": flags,
            "names_all": set(e["name_counts"].keys()),
        })

    # Optional MAC neighbor linking
    mac_by_ip4 = load_arp_ipv4() if args.mac_link else {}
    mac_by_ip6 = load_ndp_ipv6() if args.mac_link else {}

    # Merge IPv6 into IPv4 if asked (UNION-FIND + multi-phase)
    if args.merge6:
        def valid_hostish(n: str) -> bool:
            if not n: return False
            nl = n.lower()
            if nl in banned_names: return False
            if nl in known_domains: return False
            return True

        def canon_name(r: dict) -> str:
            if valid_hostish(r["resolved"]):
                return r["resolved"].lower()
            if valid_hostish(r["log_name"]):
                return r["log_name"].lower()
            return ""

        # Union-Find setup
        parent = {i: i for i in range(len(rows))}
        rank = {i: 0 for i in range(len(rows))}
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        def union(a, b):
            ra, rb = find(a), find(b)
            if ra == rb: return
            if rank[ra] < rank[rb]: parent[ra] = rb
            elif rank[ra] > rank[rb]: parent[rb] = ra
            else: parent[rb] = ra; rank[ra] += 1

        # Relation builders (collect edges then union)
        edges = []    # list of (i,j,reason)
        index_by_ip = {r["ip"]: i for i, r in enumerate(rows)}

        # 0) group by canonical name (resolved/log_name)
        by_canon: Dict[str, List[int]] = defaultdict(list)
        for i, r in enumerate(rows):
            cn = canon_name(r)
            if cn:
                by_canon[cn].append(i)
        for cn, idxs in by_canon.items():
            for k in range(1, len(idxs)):
                edges.append((idxs[0], idxs[k], "CANON_NAME"))

        # 1) Unambiguous log-name v4<->v6 link
        name_to_v4: Dict[str, List[int]] = defaultdict(list)
        name_to_v6: Dict[str, List[int]] = defaultdict(list)
        def mergeable_logname(n: str) -> bool:
            if not n: return False
            nl = n.lower()
            if nl in banned_names or nl in known_domains: return False
            return True
        for i, r in enumerate(rows):
            for nm in r["names_all"]:
                nl = nm.lower()
                if not mergeable_logname(nl): continue
                if r["v"] == 4: name_to_v4[nl].append(i)
                elif r["v"] == 6: name_to_v6[nl].append(i)
        for nm in set(name_to_v4) & set(name_to_v6):
            v4_list, v6_list = name_to_v4[nm], name_to_v6[nm]
            if len(v4_list) == 1 and len(v6_list) == 1:
                i4, i6 = v4_list[0], v6_list[0]
                r4, r6 = rows[i4], rows[i6]
                if r4["resolved"] and r6["resolved"] and r4["resolved"].lower() != r6["resolved"].lower():
                    pass
                else:
                    edges.append((i4, i6, "LOGNAME"))

        # 2) MAC neighbor linking
        if args.mac_link:
            for i, r in enumerate(rows):
                if r["v"] == 4 and r["ip"] in mac_by_ip4:
                    mac = mac_by_ip4[r["ip"]]
                    # find v6 rows with same mac
                    for j, rv6 in enumerate(rows):
                        if rv6["v"] == 6 and mac_by_ip6.get(rv6["ip"]) == mac:
                            edges.append((i, j, "MAC"))

        # Union all edges
        for a, b, _ in edges:
            union(a, b)

        # Build components for phased DNS correlation
        def components_map():
            comps = defaultdict(set)
            for i in range(len(rows)): comps[find(i)].add(i)
            return comps

        # PHASE 1: v4-only comps → AAAA (and synthesized FQDNs) → union v6 rows
        comps = components_map()
        for root, idxs in list(comps.items()):
            v4_idxs = [i for i in idxs if rows[i]["v"] == 4]
            v6_idxs = [i for i in idxs if rows[i]["v"] == 6]
            if v4_idxs and not v6_idxs:
                names = set(rows[i]["resolved"] for i in v4_idxs if rows[i]["resolved"])
                if not names:
                    for i in v4_idxs:
                        ln = rows[i]["log_name"]
                        if ln and "." in ln and valid_hostish(ln): names.add(ln)
                # synthesize from short+domain if asked
                if args.synth and known_domains:
                    shorts = set()
                    for i in v4_idxs:
                        _, sh, _ = best_name_pair(rows[i])
                        if sh: shorts.add(sh)
                    for sh in shorts:
                        for d in known_domains:
                            names.add(f"{sh}.{d}")
                for nm in sorted(names):
                    # AAAA for nm
                    for v6 in forward_lookup_AAAA(nm, args.dns):
                        j = index_by_ip.get(v6)
                        if j is not None and rows[j]["v"] == 6:
                            union(v4_idxs[0], j)
                            if args.why_merge:
                                rows[v4_idxs[0]]["flags"].add("MERGED_BY_AAAA")
                                rows[j]["flags"].add("MERGED_BY_AAAA")
                                if nm not in (rows[v4_idxs[0]]["resolved"], rows[v4_idxs[0]]["log_name"]):
                                    rows[v4_idxs[0]]["flags"].add("MERGED_BY_SYNTH_FQDN")

        # PHASE 2: v6-only comps → A (and synthesized FQDNs) → union v4 rows
        comps = components_map()
        for root, idxs in list(comps.items()):
            v4_idxs = [i for i in idxs if rows[i]["v"] == 4]
            v6_idxs = [i for i in idxs if rows[i]["v"] == 6]
            if v6_idxs and not v4_idxs:
                names = set(rows[i]["resolved"] for i in v6_idxs if rows[i]["resolved"])
                if not names:
                    for i in v6_idxs:
                        ln = rows[i]["log_name"]
                        if ln and "." in ln and valid_hostish(ln): names.add(ln)
                if args.synth and known_domains:
                    shorts = set()
                    for i in v6_idxs:
                        _, sh, _ = best_name_pair(rows[i])
                        if sh: shorts.add(sh)
                    for sh in shorts:
                        for d in known_domains:
                            names.add(f"{sh}.{d}")
                for nm in sorted(names):
                    for v4 in forward_lookup_A(nm, args.dns):
                        j = index_by_ip.get(v4)
                        if j is not None and rows[j]["v"] == 4:
                            union(v6_idxs[0], j)
                            if args.why_merge:
                                rows[v6_idxs[0]]["flags"].add("MERGED_BY_A")
                                rows[j]["flags"].add("MERGED_BY_A")
                                if nm not in (rows[v6_idxs[0]]["resolved"], rows[v6_idxs[0]]["log_name"]):
                                    rows[v6_idxs[0]]["flags"].add("MERGED_BY_SYNTH_FQDN")

        # PHASE 3: last-ditch name fallback (FQDN then unique short)
        comps = components_map()
        # Build v4-only name maps
        fqdn_to_comp: Dict[str, int] = {}
        short_to_comp: Dict[str, int] = {}
        fqdn_counts: Dict[str, int] = defaultdict(int)
        short_counts: Dict[str, int] = defaultdict(int)
        comp_names: Dict[int, Dict[str, Set[str]]] = {}

        for root, idxs in comps.items():
            v4_idxs = [i for i in idxs if rows[i]["v"] == 4]
            v6_idxs = [i for i in idxs if rows[i]["v"] == 6]
            if v4_idxs and not v6_idxs:
                fqdns, shorts = set(), set()
                for i in v4_idxs:
                    nm, sh, dom = best_name_pair(rows[i])
                    if nm and valid_hostish(nm): fqdns.add(nm)
                    if sh: shorts.add(sh)
                comp_names[root] = {"fqdn": fqdns, "short": shorts}
                for f in fqdns: fqdn_counts[f] += 1
                for s in shorts: short_counts[s] += 1

        for root, d in comp_names.items():
            for f in d["fqdn"]:
                if fqdn_counts[f] == 1: fqdn_to_comp[f] = root
            for s in d["short"]:
                if short_counts[s] == 1: short_to_comp[s] = root

        for root, idxs in list(comps.items()):
            v4_idxs = [i for i in idxs if rows[i]["v"] == 4]
            v6_idxs = [i for i in idxs if rows[i]["v"] == 6]
            if v6_idxs and not v4_idxs:
                cand_fqdns, cand_shorts = set(), set()
                for i in v6_idxs:
                    nm, sh, dom = best_name_pair(rows[i])
                    if nm and valid_hostish(nm): cand_fqdns.add(nm)
                    if sh: cand_shorts.add(sh)
                target = None
                for f in cand_fqdns:
                    if f in fqdn_to_comp:
                        target = fqdn_to_comp[f]; break
                if target is None:
                    for s in cand_shorts:
                        if s in short_to_comp:
                            target = short_to_comp[s]; break
                if target is not None:
                    any_v6 = next(iter(v6_idxs))
                    rep_v4 = next(iter([i for i in comps[target] if rows[i]["v"] == 4]))
                    union(any_v6, rep_v4)
                    if args.why_merge:
                        rows[any_v6]["flags"].add("MERGED_BY_FQDN" if cand_fqdns else "MERGED_BY_SHORT")

        # Build final components and output
        comps = defaultdict(set)
        for i in range(len(rows)): comps[find(i)].add(i)

        merged_rows = []
        consumed = set()

        for idxs in comps.values():
            v4s = sorted([i for i in idxs if rows[i]["v"] == 4], key=lambda i: ipaddress.ip_address(rows[i]["ip"]))
            v6s = sorted([i for i in idxs if rows[i]["v"] == 6], key=lambda i: ipaddress.ip_address(rows[i]["ip"]))
            if v4s and v6s:
                ipv4_addrs = [rows[i]["ip"] for i in v4s]
                ipv6_addrs = [rows[i]["ip"] for i in v6s]
                protos = set().union(*(rows[i]["protos"] for i in idxs))
                flags = set().union(*(rows[i]["flags"] for i in idxs))
                flags.add("MERGED_V4V6")
                resolved_choices = [rows[i]["resolved"] for i in idxs if rows[i]["resolved"]]
                resolved_pick = sorted(resolved_choices, key=lambda x: (-len(x), x.lower()))[0] if resolved_choices else ""
                log_choices = [rows[i]["log_name"] for i in idxs if rows[i]["log_name"]]
                def log_score(n):
                    nl = n.lower()
                    known = any(nl.endswith("." + d) or nl == d for d in known_domains)
                    return (0 if known else 1, len(n), n.lower())
                log_pick = sorted(log_choices, key=log_score)[0] if log_choices else ""
                merged_rows.append({
                    "ipv4": ";".join(ipv4_addrs),
                    "ipv6": ";".join(ipv6_addrs),
                    "log_name": log_pick,
                    "resolved": resolved_pick,
                    "protos": "|".join(sorted(protos)) if protos else "UNKNOWN",
                    "flags": "|".join(sorted(flags)) if flags else ""
                })
                consumed.update(idxs)

        for i, r in enumerate(rows):
            if i in consumed: continue
            merged_rows.append({
                "ipv4": r["ip"] if r["v"] == 4 else "",
                "ipv6": r["ip"] if r["v"] == 6 else "",
                "log_name": r["log_name"],
                "resolved": r["resolved"],
                "protos": "|".join(sorted(r["protos"])) if r["protos"] else "UNKNOWN",
                "flags": "|".join(sorted(r["flags"])) if r["flags"] else ""
            })

        merged_rows.sort(key=merged_row_sort_key)
        if args.header:
            cols = ["IPv4","IPv6","LOG_NAME","RESOLVED_NAME","PROTOS"]
            if args.flags: cols.append("FLAGS")
            print(",".join(cols))
        for m in merged_rows:
            row = [m["ipv4"], m["ipv6"], m["log_name"], m["resolved"], m["protos"]]
            if args.flags: row.append(m["flags"])
            print(",".join(row))
        return

    # Non-merged output
    if args.header:
        cols = ["IP","LOG_NAME","RESOLVED_NAME","PROTOS"]
        if args.flags: cols.append("FLAGS")
        print(",".join(cols))
    for r in rows:
        row = [r["ip"], r["log_name"], r["resolved"], "|".join(sorted(r["protos"])) if r["protos"] else "UNKNOWN"]
        if args.flags:
            row.append("|".join(sorted(r["flags"])) if r["flags"] else "")
        print(",".join(row))

if __name__ == "__main__":
    main()
