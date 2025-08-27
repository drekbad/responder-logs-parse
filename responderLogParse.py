#!/usr/bin/env python3
# (same header & imports as before)
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

DEFAULT_BANNED = {"wpad.local", "https.local"}

def normalize_proto(tok: str) -> str:
    t = tok.upper()
    if t in ("NBNS", "NETBIOS-NS"): return "NBT-NS"
    if t in ("LLMNR", "WPAD", "MDNS", "NBT-NS"): return t
    return "UNKNOWN"

def clean_ip(ip_raw: str) -> str:
    return ip_raw.split("%", 1)[0]

def ip_version(ip_s: str) -> Optional[int]:
    try: return ipaddress.ip_address(ip_s).version
    except ValueError: return None

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
            if nb and dns: out[nb] = dns
    return out

def parse_domains_and_netbios(domain_flags: List[str], netbios_flags: List[str]) -> Tuple[Set[str], Dict[str,str], Set[str]]:
    known_domains: Set[str] = set()
    known_netbios: Dict[str,str] = {}
    for d in domain_flags:
        if "=" in d:
            dns, nb = d.split("=", 1)
            dns = dns.strip().lower(); nb = nb.strip().upper()
            if dns: known_domains.add(dns)
            if dns and nb: known_netbios[nb] = dns
        else:
            dns = d.strip().lower()
            if dns: known_domains.add(dns)
    explicit_map = parse_netbios_map([n for n in netbios_flags if "=" in n])
    known_netbios.update(explicit_map)
    bare_nb = {n.strip().upper() for n in netbios_flags if "=" not in n and n.strip()}
    if bare_nb and len(known_domains) == 1:
        only_dom = next(iter(known_domains))
        for nb in bare_nb: known_netbios[nb] = only_dom
    return known_domains, known_netbios, bare_nb

def pick_log_name(names: Counter, services: Set[str], protos: Set[str],
                  known_domains: Set[str], known_netbios: Dict[str, str],
                  banned_names: Set[str]) -> Tuple[str, Set[str]]:
    flags = set(); counts = Counter()
    lower_known_domains = {d.lower() for d in known_domains}
    banned_lower = {b.lower() for b in banned_names}
    for n, c in names.items():
        u = n.upper(); nlow = n.lower()
        if u == "WPAD": continue
        if nlow in banned_lower:
            flags.add("BANNED_LOGNAME_SEEN"); continue
        if u in known_netbios: continue
        if nlow in lower_known_domains:
            flags.add("DOMAIN_ONLY_NAME_SEEN"); continue
        counts[n] += c
    if not counts: return ("", flags)
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
        candidates.append(("short_with_fqdn" if s in short_to_fqdn else "short", s))
    for n in counts:
        if is_single_label_mdns(n): mdns_single.append(n)
    candidates.extend(("mdns_single", n) for n in mdns_single)
    priority_rank = {"fqdn_known":0,"fqdn_other":1,"short_with_fqdn":2,"short":3,"mdns_single":4}
    def score(item): kind, n = item; return (priority_rank[kind], -counts[n], len(n), n.lower())
    return (min(candidates, key=score)[1], flags)

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
        if r.returncode == 0: return (r.stdout or "").strip()
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
        if not out: continue
        line = out.splitlines()[0].strip()
        if not line: continue
        if "pointer" in line: return line.split()[-1].rstrip(".")
        if "." in line: return line.rstrip(".")
    return ""

def resolve_getent(ip_s: str) -> str:
    out = run_cmd(["getent", "hosts", ip_s])
    if out:
        parts = out.split()
        if len(parts) >= 2: return parts[1].rstrip(".")
    return ""

def tcp_port_open(ip_s: str, port: int, timeout: float = 0.6) -> bool:
    try:
        fam = socket.AF_INET6 if ip_version(ip_s) == 6 else socket.AF_INET
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(timeout); s.connect((ip_s, port))
        return True
    except Exception:
        return False

NXC_NAME_RX = re.compile(r"\(name:([A-Za-z0-9_.-]+)\)")
NXC_DOM_RX  = re.compile(r"\(domain:([A-Za-z0-9_.-]+)\)")

def resolve_nxc(ip_s: str, timeout: float = 4.0) -> str:
    if not tcp_port_open(ip_s, 445, timeout=min(0.8, timeout)): return ""
    out = run_cmd(["nxc", "smb", ip_s, "--timeout", str(int(max(1, timeout)))], timeout=timeout+1.0)
    if not out: return ""
    name = ""; dom = ""
    m = NXC_NAME_RX.search(out);  m2 = NXC_DOM_RX.search(out)
    if m: name = m.group(1)
    if m2: dom = m2.group(1)
    if name and dom and "." in dom and "." not in name:
        return f"{name}.{dom}".rstrip(".")
    return name or ""

def forward_lookup_A(name: str, dns_servers: List[str]) -> List[str]:
    addrs: List[str] = []
    if not name: return addrs
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
        if not out: continue
        for line in out.splitlines():
            for t in line.strip().split():
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t): addrs.append(t)
    return sorted(set(addrs))

def forward_lookup_AAAA(name: str, dns_servers: List[str]) -> List[str]:
    """Return list of IPv6 AAAA records for a hostname (best-effort)."""
    addrs: List[str] = []
    if not name: return addrs
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
        if not out: continue
        for line in out.splitlines():
            for tok in line.strip().split():
                try:
                    ip = ipaddress.ip_address(tok)
                    if ip.version == 6:
                        addrs.append(str(ip))
                except ValueError:
                    continue
    return sorted(set(addrs))

def resolve_chain(ip_s: str, chain: List[str], dns_servers: List[str], nxc_timeout: float) -> str:
    for step in chain:
        if step == "rdns": r = resolve_rdns(ip_s)
        elif step == "dns": r = resolve_dns_tools(ip_s, dns_servers)
        elif step == "getent": r = resolve_getent(ip_s)
        elif step == "nxc": r = resolve_nxc(ip_s, timeout=nxc_timeout)
        else: r = ""
        if r: return r
    return ""

def ip_sort_key_str(ip_str: str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return (0 if addr.version == 4 else 1, addr)
    except ValueError:
        return (2, ip_str)

def merged_row_sort_key(row: dict):
    v4s = [ipaddress.ip_address(x) for x in row["ipv4"].split(";") if x]
    v6s = [ipaddress.ip_address(x) for x in row["ipv6"].split(";") if x]
    if v4s: return (0, min(v4s))
    if v6s: return (1, min(v6s))
    return (2, row.get("resolved","") or row.get("log_name",""))

def main():
    ap = argparse.ArgumentParser(description="Summarize poisoned clients by IP from Responder logs.")
    ap.add_argument("-d", "--logdir", default=DEFAULT_LOGDIR)
    ap.add_argument("--header", action="store_true")
    ap.add_argument("--domain", action="append", default=[])
    ap.add_argument("--netbios", action="append", default=[])
    ap.add_argument("--ban-name", action="append", default=[])
    ap.add_argument("--no-ban-defaults", action="store_true")
    ap.add_argument("--resolve", action="store_true")
    ap.add_argument("--resolve-chain", default="rdns")
    ap.add_argument("--dns", action="append", default=[])
    ap.add_argument("--nxc-timeout", type=float, default=4.0)
    ap.add_argument("--merge6", "--merge-v4v6", dest="merge6", action="store_true")
    ap.add_argument("--flags", action="store_true")
    args = ap.parse_args()

    known_domains, known_netbios, _ = parse_domains_and_netbios(args.domain, args.netbios)
    banned_names = set(n.strip() for n in args.ban_name if n.strip())
    if not args.no_ban_defaults: banned_names |= DEFAULT_BANNED

    chain = [t.strip().lower() for t in args.resolve_chain.split(",") if t.strip()]
    if args.resolve and args.resolve_chain == "rdns":
        chain = ["rdns", "dns", "getent", "nxc"]

    clients = defaultdict(lambda: {"version": None,"protos": set(),"name_counts": Counter(),"services": set(),"events": 0})
    for fname in LOG_FILES:
        path = os.path.join(args.logdir, fname)
        if not os.path.isfile(path): continue
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                m = LINE_RX.search(line)
                if not m: continue
                ip_s = clean_ip(m.group("ip"))
                name = (m.group("name") or "").rstrip(".,;:]")
                service = (m.group("service") or "").strip()
                protos = {normalize_proto(p) for p in PROTO_RX.findall(line)} or {"UNKNOWN"}
                e = clients[ip_s]
                e["version"] = e["version"] or ip_version(ip_s)
                e["protos"].update(protos); e["events"] += 1
                if name: e["name_counts"][name] += 1
                if service: e["services"].add(service)

    rows = []
    for ip_s in sorted(clients.keys(), key=ip_sort_key_str):
        e = clients[ip_s]; flags = set()
        log_name, pick_flags = pick_log_name(e["name_counts"], e["services"], e["protos"],
                                             known_domains, known_netbios, banned_names)
        flags |= pick_flags
        resolved = resolve_chain(ip_s, chain, args.dns, args.nxc_timeout) if chain else ""
        if log_name and log_name.lower() in known_domains:
            log_name = ""; flags.add("BLANKED_DOMAIN_LOGNAME")
        if resolved and "." in resolved and log_name:
            resolved_domain = resolved.split(".", 1)[1].lower()
            if (log_name.lower() == resolved_domain) or (
                log_name.upper() in known_netbios and known_netbios[log_name.upper()].lower() == resolved_domain
            ):
                log_name = ""; flags.add("BLANKED_DOMAIN_LOGNAME_BY_RESOLVED")
        rows.append({
            "ip": ip_s, "v": e["version"], "log_name": log_name, "resolved": resolved,
            "protos": set(p for p in e["protos"] if p != "UNKNOWN") or {"UNKNOWN"},
            "flags": flags, "names_all": set(e["name_counts"].keys()),
        })

    if args.merge6:
        def valid_hostish(n: str) -> bool:
            if not n: return False
            nl = n.lower()
            if nl in banned_names or nl in known_domains: return False
            return True
        def canon_name(r: dict) -> str:
            if valid_hostish(r["resolved"]): return r["resolved"].lower()
            if valid_hostish(r["log_name"]): return r["log_name"].lower()
            return ""

        # --- Build initial relation sets ---
        groups: List[Set[int]] = []
        by_canon: Dict[str, Set[int]] = defaultdict(set)
        for i, r in enumerate(rows):
            cn = canon_name(r)
            if cn: by_canon[cn].add(i)
        groups.extend(by_canon.values())

        # Unambiguous log-name merges
        name_to_v4: Dict[str, List[int]] = defaultdict(list)
        name_to_v6: Dict[str, List[int]] = defaultdict(list)
        def mergeable_logname(n: str) -> bool:
            if not n: return False
            nl = n.lower()
            if nl in banned_names or nl in known_domains: return False
            return True
        for i, r in enumerate(rows):
            for nm in r["names_all"]:
                if mergeable_logname(nm):
                    (name_to_v4 if r["v"] == 4 else name_to_v6)[nm.lower()].append(i)
        for nm in set(name_to_v4) & set(name_to_v6):
            v4_list, v6_list = name_to_v4[nm], name_to_v6[nm]
            if len(v4_list) == 1 and len(v6_list) == 1:
                i4, i6 = v4_list[0], v6_list[0]
                r4, r6 = rows[i4], rows[i6]
                if r4["resolved"] and r6["resolved"] and r4["resolved"].lower() != r6["resolved"].lower():
                    pass
                else:
                    rows[i4]["flags"].add("MERGED_BY_LOGNAME")
                    rows[i6]["flags"].add("MERGED_BY_LOGNAME")
                    groups.append({i4, i6})

        # Union-Find
        parent = {i: i for i in range(len(rows))}
        rank = {i: 0 for i in range(len(rows))}
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]; x = parent[x]
            return x
        def union(a,b):
            ra, rb = find(a), find(b)
            if ra == rb: return
            if rank[ra] < rank[rb]: parent[ra] = rb
            elif rank[ra] > rank[rb]: parent[rb] = ra
            else: parent[rb] = ra; rank[ra] += 1
        for idxset in groups:
            idxs = list(idxset)
            for k in range(1, len(idxs)): union(idxs[0], idxs[k])

        # Index maps for quick unions in PHASE 1/2
        ip_to_index = {r["ip"]: i for i, r in enumerate(rows)}

        # ---- PHASE 1: v4-only components → AAAA → union v6 rows (preferred) ----
        components: Dict[int, Set[int]] = defaultdict(set)
        for i in range(len(rows)): components[find(i)].add(i)
        for comp_idxs in list(components.values()):
            v4_idxs = [i for i in comp_idxs if rows[i]["v"] == 4]
            v6_idxs = [i for i in comp_idxs if rows[i]["v"] == 6]
            if v4_idxs and not v6_idxs:
                # Gather candidate hostnames (resolved first, else FQDN-like log_names)
                names = set(r["resolved"] for i in v4_idxs if (r:=rows[i])["resolved"])
                if not names:
                    for i in v4_idxs:
                        ln = rows[i]["log_name"]
                        if ln and "." in ln and valid_hostish(ln): names.add(ln)
                # For each name, get AAAA and union any *existing* v6 rows
                for nm in names:
                    for v6 in forward_lookup_AAAA(nm, args.dns):
                        j = ip_to_index.get(v6)
                        if j is not None and rows[j]["v"] == 6:
                            union(v4_idxs[0], j)  # link into this component

        # ---- PHASE 2: v6-only components → A → union v4 rows (only if still no v4) ----
        components = defaultdict(set)
        for i in range(len(rows)): components[find(i)].add(i)
        for comp_idxs in list(components.values()):
            v4_idxs = [i for i in comp_idxs if rows[i]["v"] == 4]
            v6_idxs = [i for i in comp_idxs if rows[i]["v"] == 6]
            if v6_idxs and not v4_idxs:
                names = set(r["resolved"] for i in v6_idxs if (r:=rows[i])["resolved"])
                if not names:
                    for i in v6_idxs:
                        ln = rows[i]["log_name"]
                        if ln and "." in ln and valid_hostish(ln): names.add(ln)
                for nm in names:
                    for v4 in forward_lookup_A(nm, args.dns):
                        j = ip_to_index.get(v4)
                        if j is not None and rows[j]["v"] == 4:
                            union(v6_idxs[0], j)

        # Recompute final components
        components = defaultdict(set)
        for i in range(len(rows)): components[find(i)].add(i)

        merged_rows = []
        consumed = set()
        for comp in components.values():
            v4s = sorted([i for i in comp if rows[i]["v"] == 4], key=lambda i: ipaddress.ip_address(rows[i]["ip"]))
            v6s = sorted([i for i in comp if rows[i]["v"] == 6], key=lambda i: ipaddress.ip_address(rows[i]["ip"]))
            if v4s and v6s:
                ipv4_addrs = [rows[i]["ip"] for i in v4s]
                ipv6_addrs = [rows[i]["ip"] for i in v6s]
                protos = set().union(*(rows[i]["protos"] for i in comp))
                flags = set().union(*(rows[i]["flags"] for i in comp))
                flags.add("MERGED_V4V6")
                resolved_choices = [rows[i]["resolved"] for i in comp if rows[i]["resolved"]]
                resolved_pick = sorted(resolved_choices, key=lambda x: (-len(x), x.lower()))[0] if resolved_choices else ""
                log_choices = [rows[i]["log_name"] for i in comp if rows[i]["log_name"]]
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
                consumed.update(comp)

        # Add leftovers (unchanged)
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
        if args.flags: row.append("|".join(sorted(r["flags"])) if r["flags"] else "")
        print(",".join(row))

if __name__ == "__main__":
    main()
