#!/usr/bin/env python3
"""
Network Topology Maker v3.0 -- Single File
Windows + Linux | Nmap XML Input OR Live Traceroute
Output style: nmap_traceroute_analyzer compact CIDR tree
"""

import ipaddress, json, os, platform, re, socket, struct
import subprocess, sys, time, xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_OS = platform.system()

# ── Windows UTF-8 fix ─────────────────────────────────────────────────
def _fix_win_encoding():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

_fix_win_encoding()

# ── Windows VT/ANSI colour enable ────────────────────────────────────
def _enable_win_ansi():
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass

_enable_win_ansi()

USE_COLOR = sys.stdout.isatty()


# =====================================================================
# SECTION 1 -- Terminal helpers / color / validated prompts
# =====================================================================

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def bold(t):    return _c("1",  t)
def dim(t):     return _c("2",  t)
def cyan(t):    return _c("96", t)
def green(t):   return _c("92", t)
def yellow(t):  return _c("93", t)
def red(t):     return _c("91", t)
def magenta(t): return _c("95", t)
def blue(t):    return _c("94", t)
def white(t):   return _c("97", t)

def _strip_ansi(s):
    return re.sub(r'\x1b\[[0-9;]*m', '', s)

def _p(text=""):
    try:
        print(text)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", "ascii") or "ascii"
        print(_strip_ansi(text).encode(enc, errors="replace").decode(enc))

W = 64   # box width

def _box_top():
    _p(cyan("+" + "=" * (W-2) + "+"))

def _box_mid():
    _p(cyan("+" + "-" * (W-2) + "+"))

def _box_bot():
    _p(cyan("+" + "=" * (W-2) + "+"))

def _box_row(text, fg=None, center=False):
    vis  = len(_strip_ansi(text))
    pad  = max(0, W - 4 - vis)
    colored = (globals()[fg](text) if fg and fg in globals() else text)
    if center:
        lp = pad // 2; rp = pad - lp
        _p(cyan("|") + " " + " "*lp + colored + " "*rp + " " + cyan("|"))
    else:
        _p(cyan("|") + " " + colored + " "*pad + " " + cyan("|"))

def _sec(title):
    _p()
    _p(bold(cyan("  >> " + title)))
    _p(cyan("  " + "-" * 58))

def banner():
    _p()
    _box_top()
    _box_row("Network Topology Maker  v3.0", fg="yellow", center=True)
    _box_row("Nmap XML  |  Live Traceroute  |  Windows + Linux", center=True)
    _box_bot()
    _p()

def _fmt_hint(legal):
    _p(f"  {dim('Legal format: ')}{cyan(legal)}")

def ask_raw(prompt, default=None):
    hint = f" [{default}]" if default is not None else ""
    while True:
        try:
            val = input(f"\n  {bold('>')} {prompt}{hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            _p(f"\n{yellow('Interrupted. Exiting.')}"); sys.exit(0)
        if val: return val
        if default is not None: return default
        _p(f"  {red('X')} Required -- please enter a value.")

def ask_int(prompt, lo, hi, default):
    legal = f"whole number {lo}-{hi}  (e.g. {default})"
    while True:
        raw = ask_raw(prompt, default=str(default)).strip()
        if not re.fullmatch(r'\d+', raw):
            _p(f"  {red('X')} Digits only."); _fmt_hint(legal); continue
        v = int(raw)
        if not (lo <= v <= hi):
            _p(f"  {red('X')} Must be {lo}-{hi}."); _fmt_hint(legal); continue
        return v

def ask_float(prompt, lo, hi, default):
    legal = f"decimal number {lo}-{hi}  (e.g. {default})"
    while True:
        raw = ask_raw(prompt, default=str(default)).strip()
        if not re.fullmatch(r'\d+(\.\d+)?', raw):
            _p(f"  {red('X')} Digits and one decimal point only."); _fmt_hint(legal); continue
        v = float(raw)
        if not (lo <= v <= hi):
            _p(f"  {red('X')} Must be {lo}-{hi}."); _fmt_hint(legal); continue
        return v

def ask_port(prompt, default=80):
    return ask_int(prompt, 1, 65535, default)

def ask_port_range(prompt, default="80-443"):
    legal = "start-end  both 1-65535  (e.g. 80-443)"
    while True:
        raw = ask_raw(prompt, default=default).strip()
        if not re.fullmatch(r'\d{1,5}-\d{1,5}', raw):
            _p(f"  {red('X')} Two numbers separated by hyphen."); _fmt_hint(legal); continue
        s, e = map(int, raw.split("-"))
        if not (1 <= s <= 65535 and 1 <= e <= 65535):
            _p(f"  {red('X')} Both must be 1-65535."); _fmt_hint(legal); continue
        if s > e:
            _p(f"  {red('X')} Start must be <= end."); _fmt_hint(legal); continue
        return list(range(s, e + 1))

def ask_port_list(prompt, default="80,443,8080"):
    legal = "comma-separated 1-65535  (e.g. 80,443,8080)"
    while True:
        raw = ask_raw(prompt, default=default).strip()
        if not re.fullmatch(r'\d{1,5}(,\d{1,5})*', raw):
            _p(f"  {red('X')} Digits and commas only, no spaces."); _fmt_hint(legal); continue
        parts = [int(p) for p in raw.split(",")]
        bad = [p for p in parts if not (1 <= p <= 65535)]
        if bad:
            _p(f"  {red('X')} Invalid port(s): {bad}"); _fmt_hint(legal); continue
        return parts

def ask_filepath(prompt, default="report.txt"):
    legal = "valid file path  (e.g. report.txt  or  /tmp/report.txt)"
    illegal = '\x00<>|"\''
    while True:
        raw = ask_raw(prompt, default=default).strip()
        bad = [c for c in raw if c in illegal]
        if bad:
            _p(f"  {red('X')} Illegal character(s): {sorted(set(bad))}"); _fmt_hint(legal); continue
        if len(raw) > 512:
            _p(f"  {red('X')} Path too long (max 512)."); continue
        return raw

def ask_choice(prompt, choices, default=None):
    _p(f"\n  {bold(prompt)}")
    for i, ch in enumerate(choices, 1):
        marker = green(">") if ch == default else " "
        _p(f"  {marker} {dim(str(i)+'.')} {ch}")
    default_idx = str(choices.index(default)+1) if default in choices else None
    legal = f"number 1-{len(choices)}"
    while True:
        raw = ask_raw("Enter number", default=default_idx).strip()
        if not re.fullmatch(r'\d+', raw):
            _p(f"  {red('X')} Digits only."); _fmt_hint(legal); continue
        n = int(raw)
        if not (1 <= n <= len(choices)):
            _p(f"  {red('X')} Must be 1-{len(choices)}."); _fmt_hint(legal); continue
        return choices[n-1]

def confirm(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        raw = ask_raw(f"{prompt} ({hint})", default="y" if default else "n")
        if raw.lower() in ("y","yes"): return True
        if raw.lower() in ("n","no"):  return False
        _p(f"  {red('X')} Enter {cyan('y')} or {cyan('n')} only.")
        _fmt_hint("y  or  n")


# =====================================================================
# SECTION 2 -- Input parser
# =====================================================================

_LEGAL_TARGETS = "IPs, CIDRs, ranges or hostnames  e.g. 8.8.8.8  192.168.1.0/24  10.0.0.1-10.0.0.5"

def _validate_token(token):
    if re.search(r'[\x00-\x1f\x7f]', token):
        return False, "contains control character"
    if token.count("/") > 1:
        return False, "too many '/' -- CIDR is x.x.x.x/nn"
    if not re.match(r'^[0-9a-fA-F.:/_\-]+$', token):
        bad = sorted(set(c for c in token if not re.match(r'[0-9a-fA-F.:/_\-]', c)))
        return False, f"illegal character(s) {bad}"
    return True, ""

def parse_targets(raw_tokens):
    resolved = []; seen = set()
    def _add(ip):
        if ip not in seen: seen.add(ip); resolved.append(ip)
    for token in raw_tokens:
        token = token.strip()
        if not token: continue
        ok, reason = _validate_token(token)
        if not ok:
            raise ValueError(f"'{token}' -- {reason}\n    Legal format: {_LEGAL_TARGETS}")
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                hosts = list(net.hosts())
                [_add(str(h)) for h in hosts] if hosts else _add(str(net.network_address))
                continue
            except ValueError:
                raise ValueError(f"'{token}' invalid CIDR.\n    e.g. 192.168.1.0/24")
        if "-" in token and token.count(".") >= 3:
            parts = token.split("-", 1)
            try:
                s = int(ipaddress.IPv4Address(parts[0].strip()))
                e = int(ipaddress.IPv4Address(parts[1].strip()))
                if s > e: raise ValueError(f"Range start > end: '{token}'")
                [_add(str(ipaddress.IPv4Address(n))) for n in range(s, e+1)]
                continue
            except (ValueError, ipaddress.AddressValueError) as ex:
                if "start > end" in str(ex): raise
        try:
            _add(str(ipaddress.ip_address(token))); continue
        except ValueError:
            pass
        if not re.fullmatch(r'[a-zA-Z0-9.\-]+', token):
            raise ValueError(f"'{token}' invalid hostname.\n    Letters, digits, dots, hyphens only.")
        try:
            for info in socket.getaddrinfo(token, None):
                try: _add(str(ipaddress.ip_address(info[4][0])))
                except ValueError: pass
        except socket.gaierror:
            raise ValueError(f"Cannot resolve '{token}'.\n    Check spelling or use IP directly.")
    if not resolved:
        raise ValueError(f"No valid targets.\n    Legal format: {_LEGAL_TARGETS}")
    return resolved


# =====================================================================
# SECTION 3 -- CIDR engine  (strict RFC-4632, /24 minimum grouping)
# =====================================================================

_MIN_PREFIX = 24

def _ip_to_int(ip):  return int(ipaddress.IPv4Address(ip))
def _int_to_ip(n):   return str(ipaddress.IPv4Address(n))

def _common_prefix_len(ints):
    if not ints: return 0
    if len(ints) == 1: return 32
    xor = 0
    for v in ints: xor |= (ints[0] ^ v)
    return 0 if xor >= (1 << 32) else (32 - xor.bit_length() if xor else 32)

def _valid_cidr_block(ints, plen):
    if not ints or not (0 <= plen <= 32): return False
    mask = 0xFFFFFFFF ^ ((1 << (32-plen)) - 1)
    net  = ints[0] & mask
    return all((ip & mask) == net for ip in ints)

def _aggregate_cidrs(ip_ints):
    if not ip_ints: return []
    remaining = sorted(set(ip_ints)); result = []
    while remaining:
        first = remaining[0]; best = 32
        for plen in range(31, _MIN_PREFIX-1, -1):
            size = 1 << (32-plen); mask = 0xFFFFFFFF ^ (size-1)
            net  = first & mask;    hi   = net + size - 1
            blk  = [ip for ip in remaining if net <= ip <= hi]
            if len(blk) < 2: continue
            if not _valid_cidr_block(blk, plen): break
            if _common_prefix_len(blk) != plen:  break
            best = plen
        size = 1 << (32-best); mask = 0xFFFFFFFF ^ (size-1)
        block = ipaddress.IPv4Network(f"{_int_to_ip(first & mask)}/{best}", strict=False)
        result.append(block)
        lo = int(block.network_address); hi = int(block.broadcast_address)
        remaining = [ip for ip in remaining if not (lo <= ip <= hi)]
    return result

def compute_subnets(ip_list):
    valid = []; ipv6 = []
    for ip in ip_list:
        ip = ip.strip()
        if not ip or ip == "*": continue
        try:
            obj = ipaddress.ip_address(ip)
            (ipv6 if obj.version == 6 else valid).append(str(obj))
        except ValueError: continue
    valid = list(dict.fromkeys(valid))
    if not valid:
        return {"groups": [], "total_ips": 0, "total_groups": 0,
                "host_entries": 0, "ipv6_ips": ipv6}
    blocks = _aggregate_cidrs([_ip_to_int(ip) for ip in valid])
    groups = []; hosts = 0
    for blk in blocks:
        plen = blk.prefixlen
        lo = int(blk.network_address); hi = int(blk.broadcast_address)
        members = sorted([ip for ip in valid if lo <= _ip_to_int(ip) <= hi], key=_ip_to_int)
        is_host = (plen == 32)
        if is_host: hosts += 1
        groups.append({"cidr": str(blk), "prefix_len": plen,
                       "network": str(blk.network_address),
                       "broadcast": str(blk.broadcast_address),
                       "size": blk.num_addresses, "is_host": is_host, "ips": members})
    return {"groups": groups, "total_ips": len(valid),
            "total_groups": len(groups), "host_entries": hosts, "ipv6_ips": ipv6}


# =====================================================================
# SECTION 4 -- Grouping engine
# (gateway -> dest CIDRs, exactly like nmap_traceroute_analyzer.py)
# =====================================================================

def _net_sort_key(cidr):
    n = ipaddress.ip_network(cidr, strict=False)
    return (n.network_address, n.prefixlen)

def _ip_sort_key(ip):
    try:    return int(ipaddress.ip_address(ip))
    except: return 0

def build_gateway_tree(dest_last_hop: Dict[str, Optional[str]],
                       dest_hostname:  Dict[str, str],
                       dest_hop_count: Dict[str, int]) -> Dict:
    """
    Group destination IPs by their last-hop gateway, collapse each
    gateway's destinations to minimal CIDRs (same logic as
    nmap_traceroute_analyzer.py build_groups + _merge_sibling_cidrs).

    Returns:
    {
      gw_ip: {
        "cidrs": {
          cidr_str: [ {dest, hostname, hop_count}, ... ]
        },
        "supernet": str or ""
      }
    }
    """
    gw_to_dests = defaultdict(list)
    for dest, gw in dest_last_hop.items():
        gw_to_dests[gw if gw else "(no gateway)"].append(dest)

    tree = {}
    for gw, dests in gw_to_dests.items():
        # Collapse destinations to minimal CIDRs
        try:
            nets      = [ipaddress.ip_network(d+"/32", strict=False) for d in dests]
            collapsed = list(ipaddress.collapse_addresses(nets))
            cidr_strs = [str(c) for c in collapsed]
        except Exception:
            cidr_strs = [d+"/32" for d in dests]

        # Map each dest to its CIDR
        dest_to_cidr = {}
        for cidr in cidr_strs:
            net = ipaddress.ip_network(cidr, strict=False)
            for d in dests:
                try:
                    if ipaddress.ip_address(d) in net:
                        dest_to_cidr[d] = cidr
                except ValueError:
                    pass

        # Build cidr -> entries
        cidrs_dict = defaultdict(list)
        for d in sorted(dests, key=_ip_sort_key):
            cidr = dest_to_cidr.get(d, d+"/32")
            cidrs_dict[cidr].append({
                "dest":      d,
                "hostname":  dest_hostname.get(d, ""),
                "hop_count": dest_hop_count.get(d, 0),
            })

        # Supernet
        supernet = ""
        if len(cidr_strs) > 1:
            try:
                candidate = ipaddress.ip_network(cidr_strs[0], strict=False)
                for _ in range(129):
                    all_nets = [ipaddress.ip_network(c, strict=False) for c in cidr_strs]
                    if all(n.subnet_of(candidate) or n == candidate for n in all_nets):
                        supernet = str(candidate); break
                    if candidate.prefixlen == 0: break
                    candidate = candidate.supernet()
            except Exception:
                pass

        tree[gw] = {
            "cidrs":    dict(sorted(cidrs_dict.items(), key=lambda x: _net_sort_key(x[0]))),
            "supernet": supernet,
        }

    return tree


# =====================================================================
# SECTION 5 -- Nmap XML parser
# =====================================================================

def _nmap_parse_xml(xml_path):
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise ValueError(f"Cannot parse XML '{xml_path}': {exc}")
    root = tree.getroot()
    meta = {"args": root.get("args",""), "startstr": root.get("startstr",""),
            "source": str(xml_path)}
    hosts = {}
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") == "down":
            continue
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address[@addrtype='ipv6']")
        if addr_el is None: continue
        dest_ip = addr_el.get("addr","").strip()
        if not dest_ip: continue

        hostname = ""
        hns = host_el.find("hostnames")
        if hns is not None:
            hn = hns.find("hostname")
            if hn is not None: hostname = hn.get("name","")

        hops = []
        trace_el = host_el.find("trace")
        if trace_el is not None:
            for h in sorted(trace_el.findall("hop"), key=lambda x: int(x.get("ttl",0))):
                rtt_s = h.get("rtt", None)
                try:    rtt_ms = float(rtt_s) if rtt_s else None
                except: rtt_ms = None
                hops.append({"ttl": int(h.get("ttl",0)),
                             "ip":  h.get("ipaddr","*").strip() or "*",
                             "rtt_ms": rtt_ms})

        last_hop = None
        for h in reversed(hops):
            if h["ip"] != "*" and h["ip"] != dest_ip:
                last_hop = h["ip"]; break

        hosts[dest_ip] = {"hostname": hostname, "hops": hops, "last_hop": last_hop}
    return hosts, meta


def _nmap_build_tr_results(hosts):
    tr = {}
    for dest, info in hosts.items():
        hops_out = []
        for h in info["hops"]:
            ip = h["ip"]; rtt = h.get("rtt_ms")
            probe = {"ip": ip, "rtt_ms": rtt, "status": "ok" if ip != "*" else "timeout"}
            hops_out.append({"ttl": h["ttl"], "ips": [ip] if ip != "*" else [], "probes": [probe]})
        completed = bool(hops_out) and dest in hops_out[-1]["ips"]
        tr[dest] = {"target": dest, "method": "nmap-xml", "completed": completed,
                    "error": None, "hops": hops_out,
                    "hostname": info.get("hostname",""), "last_hop": info.get("last_hop")}
    return tr


# =====================================================================
# SECTION 6 -- Live traceroute engine  (Windows + Linux)
# =====================================================================

def _make_probe(ip, rtt, status="ok"):
    return {"ip": ip or "*", "rtt_ms": round(rtt,3) if rtt else None, "status": status}

def _make_hop(ttl, probes):
    ips = sorted({p["ip"] for p in probes if p["ip"] != "*"})
    return {"ttl": ttl, "probes": probes, "ips": ips}

def _checksum(data):
    if len(data) % 2: data += b"\x00"
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF

def _icmp_echo_pkt(seq, pid):
    hdr = struct.pack("!BBHHH", 8, 0, 0, pid & 0xFFFF, seq)
    body = b"NetTopoTool"; chk = _checksum(hdr + body)
    return struct.pack("!BBHHH", 8, 0, chk, pid & 0xFFFF, seq) + body

def _icmp_probe(dest, ttl, timeout, pid, seq):
    try:
        tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return _make_probe(None, None, "no_permission")
    try:
        tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        rx.settimeout(timeout); t0 = time.monotonic()
        tx.sendto(_icmp_echo_pkt(seq, pid), (dest, 0))
        while True:
            try:    data, addr = rx.recvfrom(512)
            except socket.timeout: return _make_probe(None, None, "timeout")
            rtt = (time.monotonic() - t0) * 1000
            if len(data) < 21: continue
            t = data[20]
            if t in (0, 11): return _make_probe(addr[0], rtt)
            if t == 3:       return _make_probe(addr[0], rtt, "unreachable")
    finally:
        tx.close(); rx.close()
    return _make_probe(None, None, "unknown")

def _tcp_probe_scapy(dest, ttl, port, timeout):
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0
        pkt = IP(dst=dest, ttl=ttl) / TCP(dport=port, flags="S")
        t0  = time.monotonic()
        rep = sr1(pkt, timeout=timeout, verbose=0)
        rtt = (time.monotonic() - t0) * 1000
        return _make_probe(None, None, "timeout") if rep is None \
               else _make_probe(rep.src, rtt)
    except ImportError:
        return _make_probe(None, None, "scapy_unavailable")
    except Exception as e:
        return _make_probe(None, None, f"error:{e}")

def _parse_sys_tr(output):
    hops = []
    if _OS == "Windows":
        pat = re.compile(r"^\s*(\d+)\s+(?:(?:<?\d+\s*ms\s*){1,3}\s+([\d.]+)|\*\s+\*\s+\*)")
    else:
        pat = re.compile(r"^\s*(\d+)\s+(?:\*|([\w.\-]+)\s+\(?([\d.]+)\)?\s+([\d.]+)\s*ms)")
    for line in output.splitlines():
        m = pat.match(line)
        if not m: continue
        ttl_v = int(m.group(1))
        if _OS == "Windows":
            ip = m.group(2) if m.lastindex >= 2 else None; rtt = None
        else:
            ip  = m.group(3) or m.group(2)
            rtt = float(m.group(4)) if m.lastindex >= 4 and m.group(4) else None
        hops.append(_make_hop(ttl_v, [_make_probe(ip, rtt, "ok" if ip else "timeout")]))
    return hops

def _system_trace(dest, max_hops, timeout):
    if _OS == "Windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", str(int(timeout*1000)), dest]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(int(timeout)), "-I", dest]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops*timeout*2)
        return _parse_sys_tr(r.stdout)
    except Exception:
        return []


class TracerouteEngine:
    def __init__(self, max_hops=30, timeout=2.0, probes=3, privileged=False):
        self.max_hops   = max_hops
        self.timeout    = timeout
        self.probes     = probes
        self.privileged = privileged
        self._pid       = os.getpid() & 0xFFFF

    def trace(self, target, force_tcp=False, tcp_ports=None):
        tcp_ports = tcp_ports or [80]
        use_icmp  = self.privileged and not force_tcp
        res = {"target": target, "method": "icmp" if use_icmp else "tcp",
               "hops": [], "completed": False, "error": None,
               "hostname": "", "last_hop": None}
        if use_icmp:
            hops, done, err = self._icmp_trace(target)
            if err == "no_permission":
                res["method"] = "tcp"
                hops, done, err = self._tcp_trace(target, tcp_ports)
        else:
            hops, done, err = self._tcp_trace(target, tcp_ports)
        if not hops:
            _p(f"    {yellow('[!]')} Falling back to system traceroute ...")
            hops = _system_trace(target, self.max_hops, self.timeout)
            res["method"] = "system"
            done = bool(hops) and bool(hops[-1]["ips"]) and hops[-1]["ips"][-1] == target

        last_hop = None
        for hop in reversed(hops):
            if hop["ips"] and hop["ips"][0] != target:
                last_hop = hop["ips"][0]; break
        res["last_hop"] = last_hop

        res.update({"hops": hops, "completed": done, "error": err})
        return res

    def _icmp_trace(self, dest):
        hops, done = [], False
        for ttl in range(1, self.max_hops+1):
            probes = [_icmp_probe(dest, ttl, self.timeout, self._pid, ttl*10+s)
                      for s in range(self.probes)]
            hop = _make_hop(ttl, probes); hops.append(hop); self._print_hop(hop)
            if dest in hop["ips"]: done = True; break
            if (len(hops) >= 3 and
                    all(all(p["status"] == "timeout" for p in hops[-i]["probes"])
                        for i in range(1, 4))):
                break
        return hops, done, None

    def _tcp_trace(self, dest, ports):
        hops, done = [], False; port = ports[0]
        for ttl in range(1, self.max_hops+1):
            probes = [_tcp_probe_scapy(dest, ttl, port, self.timeout)
                      for _ in range(self.probes)]
            hop = _make_hop(ttl, probes); hops.append(hop); self._print_hop(hop)
            if dest in hop["ips"]: done = True; break
            if all(p["status"] == "scapy_unavailable" for p in probes):
                return [], False, "scapy_unavailable"
        return hops, done, None

    def _print_hop(self, hop):
        ttl = hop["ttl"]; ips = hop["ips"]
        if not ips:
            _p(f"    {dim(str(ttl).rjust(2))}  {dim('* * *')}"); return
        rtts = "  ".join(f"{p['rtt_ms']:.1f}ms" if p.get("rtt_ms") else "*"
                         for p in hop["probes"])
        _p(f"    {dim(str(ttl).rjust(2))}  {white(' / '.join(ips)):<22}  {dim(rtts)}")


# =====================================================================
# SECTION 7 -- Path analyser  (shared by both modes)
# =====================================================================

def analyze_paths(tr_results):
    an = {"path_divergence": [], "load_balancing": [],
          "firewall_hints": [],  "shared_hops": {}}
    ttl_map = {}
    for tgt, res in tr_results.items():
        for hop in res.get("hops", []):
            ttl_map.setdefault(hop["ttl"], {})[tgt] = set(hop["ips"])

    for ttl, tmap in ttl_map.items():
        sets = [s for s in tmap.values() if s]
        if len(sets) > 1:
            shared = set.intersection(*sets)
            if shared: an["shared_hops"][ttl] = sorted(shared)

    for ttl, tmap in ttl_map.items():
        unique = {frozenset(v) for v in tmap.values() if v}
        if len(unique) > 1:
            an["path_divergence"].append(
                {"ttl": ttl,
                 "targets": {t: sorted(ips) for t, ips in tmap.items() if ips}})

    for tgt, res in tr_results.items():
        for hop in res.get("hops", []):
            if len(hop["ips"]) > 1:
                an["load_balancing"].append(
                    {"target": tgt, "ttl": hop["ttl"], "ips": hop["ips"]})

    for tgt, res in tr_results.items():
        run = 0
        for hop in res.get("hops", []):
            if all(p["ip"] == "*" for p in hop["probes"]): run += 1
            else:
                if run >= 3:
                    an["firewall_hints"].append({"target": tgt, "consecutive_*": run,
                                                 "after_ttl": hop["ttl"] - run})
                run = 0
    return an


# =====================================================================
# SECTION 8 -- Output renderer
# (compact CIDR tree style, same as nmap_traceroute_analyzer.py)
# =====================================================================

def _render_report(mode_label, meta_lines, gw_tree, tr_results,
                   analysis, total_targets, output_fmt):
    """
    Build the complete report string in nmap_traceroute_analyzer.py style:
      Banner box -> Stats -> CIDR Tree (GW -> CIDR -> Hosts) ->
      Gateway Summary -> Path Hints -> Footer box
    """
    C = {}
    for k,v in [("R","0"),("B","1"),("D","2"),("CY","96"),("GR","92"),
                ("YE","93"),("RE","91"),("MA","95"),("BL","94"),("WH","97")]:
        C[k] = f"\033[{v}m" if USE_COLOR else ""
    R=C["R"]; B=C["B"]; D=C["D"]; CY=C["CY"]; GR=C["GR"]
    YE=C["YE"]; RE=C["RE"]; MA=C["MA"]; BL=C["BL"]; WH=C["WH"]

    if output_fmt == "json":
        return json.dumps({
            "mode":      mode_label,
            "meta":      dict(meta_lines),
            "gw_tree":   gw_tree,
            "analysis":  analysis,
        }, indent=2, default=str)

    ln = []

    # ── Banner box ──────────────────────────────────────────────────
    ln.append(f"\n{CY}+{'='*(W-2)}+{R}")
    title = f"  NETWORK TOPOLOGY REPORT  [{mode_label}]  "
    vis   = len(title)
    lp    = max(0, (W-2-vis)//2); rp = max(0, W-2-vis-lp)
    ln.append(f"{CY}|{R}{' '*lp}{B}{YE}{title}{R}{' '*rp}{CY}|{R}")
    ln.append(f"{CY}+{'-'*(W-2)}+{R}")

    # Meta rows
    for label, val in meta_lines:
        row = f"  {label:<18} {val}"
        vis = len(_strip_ansi(row))
        ln.append(f"{CY}|{R}{D}{row}{R}{' '*max(0,W-2-vis)}{CY}|{R}")
    ln.append(f"{CY}+{'='*(W-2)}+{R}")
    ln.append("")

    # ── Stats badges ────────────────────────────────────────────────
    total_gw    = len([g for g in gw_tree if g != "(no gateway)"])
    total_cidrs = sum(len(v["cidrs"]) for v in gw_tree.values())
    total_subs  = sum(
        1 for v in gw_tree.values()
        for cidr in v["cidrs"]
        if ipaddress.ip_network(cidr, strict=False).prefixlen < 32
    )

    def badge(label, val, bg, fg="0"):
        return (f"\033[{bg}m\033[{fg}m {label} {val} {R}" if USE_COLOR
                else f"[{label}: {val}]")

    stats = (badge("HOSTS",   total_targets, "42",  "30") + "  " +
             badge("GATEWAYS",total_gw,      "46",  "30") + "  " +
             badge("CIDRs",   total_cidrs,   "43",  "30") + "  " +
             badge("SUBNETS", total_subs,    "45",  "30"))
    vis_stats = len(_strip_ansi(stats))
    lp = max(0, (W-2-vis_stats)//2)
    ln.append("  " + " "*lp + stats)
    ln.append("")

    # ── CIDR Tree ───────────────────────────────────────────────────
    ln.append(f"  {B}{CY}>> CIDR TREE  --  Destination Groups by Gateway{R}")
    ln.append(f"  {CY}{'-'*58}{R}")
    ln.append("")

    sorted_gws = sorted(gw_tree.keys(),
                        key=lambda g: (_ip_sort_key(g) if g != "(no gateway)" else 2**32))

    for gw in sorted_gws:
        info   = gw_tree[gw]
        cidrs  = info["cidrs"]
        supnet = info.get("supernet","")
        n_dest = sum(len(v) for v in cidrs.values())

        # Gateway header
        gw_color = RE if gw == "(no gateway)" else MA
        gw_badge = (f"\033[45m\033[30m GW \033[0m" if USE_COLOR else "[GW]")
        ln.append(f"  {gw_color}{B}{gw}{R}  {gw_badge}  "
                  f"{D}({n_dest} host{'s' if n_dest!=1 else ''}){R}")

        if supnet:
            ln.append(f"    {D}supernet: {CY}{supnet}{R}")

        # CIDRs under this gateway
        cidr_list = sorted(cidrs.keys(), key=_net_sort_key)
        for ci, cidr in enumerate(cidr_list):
            entries  = cidrs[cidr]
            net      = ipaddress.ip_network(cidr, strict=False)
            is_last_c= (ci == len(cidr_list)-1)
            conn_c   = "`--" if is_last_c else "|--"
            is_sub   = net.prefixlen < 32

            if is_sub:
                cidr_badge = (f"\033[43m\033[30m /{net.prefixlen} \033[0m" if USE_COLOR
                              else f"[/{net.prefixlen}]")
                n_h = len(entries)
                ln.append(f"    {CY}{conn_c}{R} {GR}{B}{cidr}{R}  "
                          f"{cidr_badge}  {D}{n_h} host{'s' if n_h!=1 else ''}{R}")
            else:
                ln.append(f"    {CY}{conn_c}{R} {YE}{cidr}{R}  {D}(host){R}")

            indent = "        " if is_last_c else "    |   "
            for di, e in enumerate(sorted(entries, key=lambda x: _ip_sort_key(x["dest"]))):
                is_last_d = (di == len(entries)-1)
                conn_d    = "`--" if is_last_d else "|--"
                hn_str    = f"  {D}({e['hostname']}){R}" if e["hostname"] else ""
                hops_str  = f"  {D}[{e['hop_count']} hops]{R}" if e["hop_count"] else ""

                # Status from tr_results
                tr = tr_results.get(e["dest"], {})
                done   = tr.get("completed", False)
                method = tr.get("method", "")
                st_col = GR if done else YE
                st_sym = "+" if done else "?"
                ln.append(f"    {indent}{CY}{conn_d}{R} "
                          f"{st_col}{st_sym}{R} {WH}{B}{e['dest']}{R}"
                          f"{hn_str}{hops_str}")
        ln.append("")

    # ── Gateway summary ─────────────────────────────────────────────
    ln.append(f"  {B}{CY}>> GATEWAY SUMMARY{R}")
    ln.append(f"  {CY}{'-'*58}{R}")
    for gw in sorted_gws:
        info   = gw_tree[gw]
        cidrs  = list(info["cidrs"].keys())
        supnet = info.get("supernet","")
        n_dest = sum(len(v) for v in info["cidrs"].values())
        gw_color = RE if gw == "(no gateway)" else MA
        ln.append(f"  {gw_color}{B}{gw}{R}  {D}{n_dest} dest(s)  {len(cidrs)} CIDR(s){R}")
        if supnet:
            chk = GR + "+" + R
            ln.append(f"    {chk}  Common supernet: {CY}{supnet}{R}")
        else:
            x = (YE + "~" + R)
            ln.append(f"    {x}  {D}Non-contiguous (no common supernet){R}")
        for cidr in cidrs:
            ln.append(f"    {D}  * {cidr}{R}")
    ln.append("")

    # ── Path analysis hints ─────────────────────────────────────────
    ln.append(f"  {B}{CY}>> PATH ANALYSIS HINTS{R}")
    ln.append(f"  {CY}{'-'*58}{R}")

    lb = analysis.get("load_balancing", [])
    if lb:
        ln.append(f"  {YE}{B}Load Balancing:{R}")
        for e in lb:
            ln.append(f"    {D}TTL {e['ttl']} -> {', '.join(e['ips'])}{R}")
    else:
        ln.append(f"  {D}No load balancing detected.{R}")

    div = analysis.get("path_divergence", [])
    if div:
        ln.append(f"  {MA}{B}Path Divergence:{R}")
        for e in div[:5]:  # cap at 5
            ln.append(f"    {D}TTL {e['ttl']}:{R}")
            for t, ips in e["targets"].items():
                ln.append(f"      {D}{t} -> {', '.join(ips)}{R}")

    fw = analysis.get("firewall_hints", [])
    if fw:
        ln.append(f"  {RE}{B}Firewall / Filtering:{R}")
        for e in fw:
            ln.append(f"    {D}{e['target']}  {e['consecutive_*']}x* after TTL {e['after_ttl']}{R}")

    shared = analysis.get("shared_hops", {})
    if shared:
        ln.append(f"  {BL}{B}Shared Hops:{R}")
        for ttl in sorted(shared)[:8]:
            ln.append(f"    {D}TTL {ttl}: {', '.join(shared[ttl])}{R}")

    ln.append("")

    # ── Footer box ───────────────────────────────────────────────────
    ln.append(f"{CY}+{'='*(W-2)}+{R}")
    footer = f"  Network Topology Maker v3.0  |  {mode_label}  "
    vis = len(footer); lp = max(0,(W-2-vis)//2); rp = max(0,W-2-vis-lp)
    ln.append(f"{CY}|{R}{' '*lp}{D}{footer}{R}{' '*rp}{CY}|{R}")
    ln.append(f"{CY}+{'='*(W-2)}+{R}")
    ln.append("")

    return "\n".join(ln)


def _save_report(report, path):
    clean = re.sub(r"\033\[[0-9;]*m", "", report)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(clean)
        _p(f"\n  {green('OK')}  Saved -> {bold(path)}\n")
    except OSError as e:
        _p(f"\n  {red('!')}  Save failed: {e}\n")


# =====================================================================
# SECTION 9 -- Privilege check (Windows + Linux/macOS)
# =====================================================================

def _check_privileges():
    if _OS == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False   # safety for any other platform


def _ask_output_settings():
    from pathlib import Path
    _sec("OUTPUT SETTINGS")
    fmt = ask_choice("Output format:",
                     ["Text  (human-readable, coloured)",
                      "JSON  (machine-readable)"],
                     default="Text  (human-readable, coloured)")
    output_fmt = "text" if fmt.startswith("Text") else "json"
    save_path = None
    if confirm("Save report to a file?", default=False):
        save_path = ask_filepath("File path", default="topology_report.txt")
    return output_fmt, save_path


# =====================================================================
# MODE A -- Nmap XML
# =====================================================================

def _mode_nmap_xml():
    _sec("NMAP XML MODE")
    _p(f"""
  Provide one or more Nmap XML output files.
  {dim('Generate with:')}
    {cyan('nmap -sn --traceroute -oX scan.xml 192.168.1.0/24')}
    {cyan('nmap -sV --traceroute -oX scan.xml 10.0.0.0/8')}

  {dim('Legal format:')} {cyan('scan.xml   scan1.xml scan2.xml   /tmp/scan.xml')}
""")

    xml_paths = []
    legal_path = "valid .xml file path  (e.g. scan.xml  or  /tmp/scan.xml)"
    while True:
        raw    = ask_raw("XML file path(s)  [space-separated]")
        tokens = raw.split()
        bad_chars = [t for t in tokens if re.search(r'[\x00<>|"\']', t)]
        if bad_chars:
            _p(f"  {red('X')} Illegal characters in: {bad_chars}")
            _fmt_hint(legal_path); continue
        found = []; missing = []
        for t in tokens:
            p = Path(t)
            if p.exists() and p.suffix.lower() == ".xml":
                found.append(p)
            elif p.exists():
                _p(f"  {yellow('!')} '{t}' exists but is not .xml -- skipped.")
            else:
                missing.append(t)
        if missing:
            _p(f"  {red('X')} Not found: {missing}"); _fmt_hint(legal_path); continue
        if not found:
            _p(f"  {red('X')} No valid .xml files. Try again."); continue
        xml_paths = found; break

    all_hosts = {}; last_meta = {}
    for xp in xml_paths:
        _p(f"\n  {dim('Loading')} {bold(str(xp))} ...")
        try:
            h, m = _nmap_parse_xml(xp)
        except ValueError as e:
            _p(f"  {red('!')} {e} -- skipping."); continue
        all_hosts.update(h); last_meta = m
        with_trace = sum(1 for v in h.values() if v["hops"])
        _p(f"  {green('OK')}  {len(h)} host(s)  ({with_trace} with traceroute data)")

    if not all_hosts:
        _p(f"\n  {red('!')} No hosts found. Exiting.\n"); sys.exit(1)

    targets = sorted(all_hosts.keys(), key=_ip_sort_key)
    _p(f"\n  {green('OK')}  {len(targets)} target(s) from {len(xml_paths)} file(s)")

    output_fmt, save_path = _ask_output_settings()

    _p(f"\n  {bold('Targets      :')} {len(targets)}")
    _p(f"  {bold('XML files    :')} {', '.join(str(p.name) for p in xml_paths)}")
    _p(f"  {bold('Output format:')} {output_fmt}")
    _p(f"  {bold('Save to      :')} {save_path or dim('(no)')}\n")
    if not confirm("Run now?", default=True):
        _p(yellow("  Aborted.")); sys.exit(0)

    tr_results = _nmap_build_tr_results(all_hosts)

    # Build gateway tree from last-hop data
    dest_last_hop  = {d: info["last_hop"]  for d, info in all_hosts.items()}
    dest_hostname  = {d: info["hostname"]  for d, info in all_hosts.items()}
    dest_hop_count = {d: len(info["hops"]) for d, info in all_hosts.items()}
    gw_tree = build_gateway_tree(dest_last_hop, dest_hostname, dest_hop_count)

    analysis = analyze_paths(tr_results)

    meta_lines = [
        ("Source",    last_meta.get("source","")),
        ("Scan date", last_meta.get("startstr","n/a")),
        ("Targets",   str(len(targets))),
        ("Gateways",  str(len([g for g in gw_tree if g != "(no gateway)"]))),
    ]
    if last_meta.get("args"):
        meta_lines.append(("Nmap args", last_meta["args"][:50]))

    report = _render_report("Nmap XML", meta_lines, gw_tree,
                            tr_results, analysis, len(targets), output_fmt)
    _p(report)
    if save_path: _save_report(report, save_path)


# =====================================================================
# MODE B -- Live traceroute
# =====================================================================

def _ask_trace_params(privileged):
    _sec("TRACEROUTE SETTINGS")
    if privileged:
        proto   = ask_choice("Probe protocol:",
                             ["ICMP  (recommended -- requires root/admin)",
                              "TCP SYN  (works without root, needs Scapy)"],
                             default="ICMP  (recommended -- requires root/admin)")
        use_tcp = proto.startswith("TCP")
    else:
        _p(f"\n  {yellow('!')}  Not root/admin -- using TCP.")
        use_tcp = True

    tcp_ports = [80]
    if use_tcp:
        mode = ask_choice("TCP port mode:",
                          ["Single port",
                           "Port range  (e.g. 80-443)",
                           "Port list   (e.g. 80,443,8080)",
                           "Top 10 common ports",
                           "Top 20 common ports",
                           "Top 50 common ports"],
                          default="Single port")
        if mode == "Single port":
            tcp_ports = [ask_port("Port number", default=80)]
        elif mode.startswith("Port range"):
            tcp_ports = ask_port_range("Range (start-end)", default="80-443")
        elif mode.startswith("Port list"):
            tcp_ports = ask_port_list("Ports (comma-separated)", default="80,443,8080")
        elif "10" in mode: tcp_ports = [80,443,22,21,25,53,110,143,3306,8080]
        elif "20" in mode: tcp_ports = [80,443,22,21,25,53,110,143,3306,8080,
                                         23,3389,5900,8443,587,993,995,8000,8888,6379]
        else: tcp_ports = [80,443,22,21,25,53,110,143,3306,8080,
                           23,3389,5900,8443,587,993,995,8000,8888,6379,
                           5432,27017,6443,2375,2376,4443,9200,9300,5601,
                           11211,6380,5000,4000,7000,9090,9091,9092,15672,
                           5672,61616,2181,2888,3888,8161,61613,4369,25672,
                           5671,5673,4200]

    max_hops = ask_int("Maximum hops (TTL)", 1, 128, 30)
    timeout  = ask_float("Per-hop timeout (seconds)", 0.1, 30.0, 2.0)
    probes   = ask_int("Probes per hop", 1, 10, 3)
    return use_tcp, tcp_ports, max_hops, timeout, probes


def _mode_live(privileged):
    _sec("TARGETS")
    _p(f"""
  Enter targets separated by spaces or commas.
  {dim('Accepted:')}  IP  CIDR  range  hostname
  {dim('Examples:')}
    {cyan('8.8.8.8')}
    {cyan('8.8.8.8 1.1.1.1 9.9.9.9')}
    {cyan('192.168.1.0/24')}
    {cyan('10.0.0.1-10.0.0.10')}
    {cyan('example.com')}
""")
    while True:
        raw    = ask_raw("Targets")
        tokens = [t for t in re.split(r"[\s,]+", raw) if t]
        try:
            targets = parse_targets(tokens)
            _p(f"\n  {green('OK')} Resolved {bold(str(len(targets)))} IP(s)")
            for ip in (targets if len(targets) <= 6 else targets[:4]):
                _p(f"    {dim('*')} {ip}")
            if len(targets) > 6:
                _p(f"    {dim(f'... and {len(targets)-4} more')}")
            break
        except ValueError as e:
            _p(f"\n  {red('X')} {e}"); continue

    use_tcp, tcp_ports, max_hops, timeout, probes = _ask_trace_params(privileged)
    output_fmt, save_path = _ask_output_settings()

    proto_str = (f"TCP (ports: {', '.join(str(p) for p in tcp_ports[:3])}"
                 + (" ..." if len(tcp_ports) > 3 else "") + ")"
                 if use_tcp else "ICMP")
    _p(f"\n  {bold('Targets   :')} {len(targets)} IP(s)")
    _p(f"  {bold('Protocol  :')} {proto_str}")
    _p(f"  {bold('Max hops  :')} {max_hops}")
    _p(f"  {bold('Timeout   :')} {timeout}s")
    _p(f"  {bold('Probes/hop:')} {probes}")
    _p(f"  {bold('Output    :')} {output_fmt}")
    _p(f"  {bold('Save to   :')} {save_path or dim('(no)')}\n")
    if not confirm("Start now?", default=True):
        _p(yellow("  Aborted.")); sys.exit(0)

    _sec("RUNNING TRACEROUTES")
    engine     = TracerouteEngine(max_hops=max_hops, timeout=timeout,
                                  probes=probes, privileged=privileged)
    tr_results = {}
    for idx, ip in enumerate(targets, 1):
        _p(f"\n  {magenta(bold(f'[{idx}/{len(targets)}]'))} Tracing {bold(ip)} ...")
        res = engine.trace(ip, force_tcp=use_tcp, tcp_ports=tcp_ports)
        tr_results[ip] = res
        st = green("COMPLETE") if res["completed"] else yellow("INCOMPLETE")
        _p(f"  {dim('|_')} {st}  ({len(res['hops'])} hop(s) via {res['method']})\n")

    # Build gateway tree from live results
    dest_last_hop  = {ip: res.get("last_hop")  for ip, res in tr_results.items()}
    dest_hostname  = {ip: res.get("hostname","") for ip, res in tr_results.items()}
    dest_hop_count = {ip: len(res.get("hops",[])) for ip, res in tr_results.items()}
    gw_tree = build_gateway_tree(dest_last_hop, dest_hostname, dest_hop_count)

    analysis = analyze_paths(tr_results)
    method   = list(tr_results.values())[0]["method"] if tr_results else "?"

    meta_lines = [
        ("Method",   method),
        ("Targets",  str(len(targets))),
        ("Gateways", str(len([g for g in gw_tree if g != "(no gateway)"]))),
        ("Max hops", str(max_hops)),
    ]

    report = _render_report("Live Traceroute", meta_lines, gw_tree,
                            tr_results, analysis, len(targets), output_fmt)
    _p(report)
    if save_path: _save_report(report, save_path)


# =====================================================================
# ENTRY POINT
# =====================================================================

def main():
    banner()
    privileged = _check_privileges()
    if privileged:
        _p(f"  {green('OK')}  Elevated privileges -- ICMP available.\n")
    else:
        _p(f"  {yellow('!')}  No root/admin -- ICMP unavailable, TCP will be used.\n")

    _sec("SELECT INPUT MODE")
    _p(f"""
  {bold(cyan('1. Nmap XML'))}   -- Load existing Nmap scan XML (no live probing)
               {dim('nmap --traceroute -oX scan.xml <targets>')}

  {bold(cyan('2. Live Trace'))} -- Probe targets interactively right now
               {dim('ICMP needs root/admin  |  TCP fallback available')}
""")
    mode = ask_choice("Choose mode:",
                      ["Nmap XML file input",
                       "Live traceroute"],
                      default="Nmap XML file input")

    if mode.startswith("Nmap"):
        _mode_nmap_xml()
    else:
        _mode_live(privileged)


if __name__ == "__main__":
    main()
