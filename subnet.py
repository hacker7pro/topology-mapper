#!/usr/bin/env python3
"""
nmap_traceroute_analyzer.py
============================
Cross-platform (Windows & Linux) Nmap XML traceroute investigator.

Usage
-----
    python nmap_traceroute_analyzer.py scan.xml
    python nmap_traceroute_analyzer.py scan1.xml scan2.xml
    python nmap_traceroute_analyzer.py scan.xml --no-color
    python nmap_traceroute_analyzer.py scan.xml --ascii
"""

import argparse
import ipaddress
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from datetime import datetime

# ================================================================
# Windows UTF-8 fix — must run before any print()
# ================================================================
def _fix_windows_encoding():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

_fix_windows_encoding()


def _terminal_supports_unicode() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.kernel32.GetConsoleOutputCP() == 65001
        except Exception:
            return False
    enc = (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "")
    return "utf8" in enc

_UNICODE_TERM = _terminal_supports_unicode()


# ================================================================
# Symbol tables — Unicode vs ASCII fallback
# ================================================================
_SYM_U = {
    "dbl_h":    "\u2550",   # ═
    "sgl_h":    "\u2500",   # ─
    "tee":      "\u251c\u2500",  # ├─
    "cor":      "\u2514\u2500",  # └─
    "pipe":     "\u2502",   # │
    "dbl_tl":   "\u2554",   # ╔
    "dbl_tr":   "\u2557",   # ╗
    "dbl_bl":   "\u255a",   # ╚
    "dbl_br":   "\u255d",   # ╝
    "dbl_lm":   "\u2560",   # ╠
    "dbl_rm":   "\u2563",   # ╣
    "bullet":   "\u25cf",   # ●
    "diamond":  "\u25c6",   # ◆
    "arrow_r":  "\u25b6",   # ▶
    "check":    "\u2714",   # ✔
    "cross":    "\u2718",   # ✘
    "net_icon": "\u26a1",   # ⚡  (network/gateway)
    "cidr_icon":"\u25a0",   # ■
    "host_icon":"\u25cb",   # ○
    "warn":     "\u26a0",   # ⚠
}
_SYM_A = {
    "dbl_h":    "=",
    "sgl_h":    "-",
    "tee":      "+--",
    "cor":      "+--",
    "pipe":     "|",
    "dbl_tl":   "+",
    "dbl_tr":   "+",
    "dbl_bl":   "+",
    "dbl_br":   "+",
    "dbl_lm":   "+",
    "dbl_rm":   "+",
    "bullet":   "*",
    "diamond":  "*",
    "arrow_r":  ">",
    "check":    "[+]",
    "cross":    "[x]",
    "net_icon": ">>",
    "cidr_icon":"#",
    "host_icon":"o",
    "warn":     "[!]",
}

def S(key, u): return (_SYM_U if u else _SYM_A)[key]


# ================================================================
# Colour helpers
# ================================================================
try:
    import colorama
    colorama.init(autoreset=True)
    _C = {
        "reset":        colorama.Style.RESET_ALL,
        "bold":         colorama.Style.BRIGHT,
        "dim":          colorama.Style.DIM,
        "cyan":         colorama.Fore.CYAN,
        "yellow":       colorama.Fore.YELLOW,
        "green":        colorama.Fore.GREEN,
        "blue":         colorama.Fore.BLUE,
        "magenta":      colorama.Fore.MAGENTA,
        "red":          colorama.Fore.RED,
        "white":        colorama.Fore.WHITE,
        "black":        colorama.Fore.BLACK,
        "bg_blue":      colorama.Back.BLUE,
        "bg_cyan":      colorama.Back.CYAN,
        "bg_magenta":   colorama.Back.MAGENTA,
        "bg_green":     colorama.Back.GREEN,
        "bg_yellow":    colorama.Back.YELLOW,
        "bg_red":       colorama.Back.RED,
        "bg_black":     colorama.Back.BLACK,
        "bg_white":     colorama.Back.WHITE,
    }
    HAS_COLOR = True
except ImportError:
    _C = {k: "" for k in (
        "reset","bold","dim","cyan","yellow","green","blue","magenta",
        "red","white","black","bg_blue","bg_cyan","bg_magenta","bg_green",
        "bg_yellow","bg_red","bg_black","bg_white"
    )}
    HAS_COLOR = False


def _c(key, text, uc):
    return f"{_C[key]}{_C['bold']}{text}{_C['reset']}" if uc else text

def _cf(fg, text, uc):
    return f"{_C[fg]}{text}{_C['reset']}" if uc else text

def _cb(fg, bg, text, uc):
    return f"{_C[bg]}{_C[fg]}{_C['bold']} {text} {_C['reset']}" if uc else f"[{text}]"

def _p(text="", **kw):
    try:
        print(text, **kw)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", "ascii") or "ascii"
        print(text.encode(enc, errors="replace").decode(enc), **kw)

def _dim(text, uc):
    return f"{_C['dim']}{text}{_C['reset']}" if uc else text


# ================================================================
# Box drawing helpers
# ================================================================
def _box_top(width, u, uc):
    tl = S("dbl_tl", u); tr = S("dbl_tr", u); h = S("dbl_h", u)
    line = tl + h * (width - 2) + tr
    _p(_cf("cyan", line, uc))

def _box_bot(width, u, uc):
    bl = S("dbl_bl", u); br = S("dbl_br", u); h = S("dbl_h", u)
    line = bl + h * (width - 2) + br
    _p(_cf("cyan", line, uc))

def _box_mid(width, u, uc):
    lm = S("dbl_lm", u); rm = S("dbl_rm", u); h = S("dbl_h", u)
    line = lm + h * (width - 2) + rm
    _p(_cf("cyan", line, uc))

def _box_row(text, width, u, uc, fg="white", center=False):
    pipe = S("dbl_h", u)[0] if not u else "\u2551"  # ║
    if not u: pipe = "|"
    inner = width - 4
    if center:
        content = text.center(inner)
    else:
        content = text.ljust(inner)
    # strip ansi for length calc — approximate
    visible_len = len(_strip_ansi(text))
    pad = inner - visible_len
    if center:
        lpad = pad // 2
        rpad = pad - lpad
        row = pipe + " " + " "*lpad + text + " "*rpad + " " + pipe
    else:
        row = pipe + " " + text + " "*max(0, pad) + " " + pipe
    _p(_cf("cyan", pipe, uc) + " " + text + " "*max(0, pad) + " " + _cf("cyan", pipe, uc))

def _strip_ansi(s):
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', s)


# ================================================================
# XML parsing
# ================================================================
def parse_nmap_xml(xml_path: Path) -> dict:
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        _p(f"[ERROR] Cannot parse {xml_path}: {exc}", file=sys.stderr)
        return {}

    results = {}
    root = tree.getroot()
    scanner_args = root.get("args", "")
    scan_start   = root.get("startstr", "")

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        dest_ip = addr_el.get("addr", "").strip()
        if not dest_ip:
            continue

        hostname = ""
        hns = host.find("hostnames")
        if hns is not None:
            hn = hns.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        hop_ips = []
        trace = host.find("trace")
        if trace is not None:
            for hop in sorted(trace.findall("hop"), key=lambda h: int(h.get("ttl", 0))):
                hop_ips.append(hop.get("ipaddr", "*").strip() or "*")

        last_hop = None
        for ip in reversed(hop_ips):
            if ip != "*" and ip != dest_ip:
                last_hop = ip
                break

        results[dest_ip] = {
            "last_hop": last_hop,
            "hostname": hostname,
            "hop_count": len(hop_ips),
        }

    return results, {"args": scanner_args, "startstr": scan_start}


# ================================================================
# CIDR utilities
# ================================================================
def collapse_to_cidrs(ip_list):
    nets = []
    for ip in ip_list:
        try:
            nets.append(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            pass
    return [str(n) for n in ipaddress.collapse_addresses(nets)] if nets else []


def cidr_display(cidr_str):
    net = ipaddress.ip_network(cidr_str, strict=False)
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else cidr_str


def find_tightest_supernet(cidr_list):
    if len(cidr_list) < 2:
        return ""
    try:
        nets = [ipaddress.ip_network(c, strict=False) for c in cidr_list]
        if len(set(n.version for n in nets)) > 1:
            return ""
        start = max(nets, key=lambda n: n.prefixlen)
        candidate = start
        for _ in range(129):
            if all(n.subnet_of(candidate) or n == candidate for n in nets):
                return str(candidate)
            if candidate.prefixlen == 0:
                break
            candidate = candidate.supernet()
    except Exception:
        pass
    return ""


# ================================================================
# Core grouping
# ================================================================
def build_groups(all_data):
    gateway_to_dests = defaultdict(list)
    no_gateway = []

    for dest_ip, info in all_data.items():
        gw = info["last_hop"]
        (gateway_to_dests[gw] if gw else no_gateway).append(dest_ip)

    cidr_tree = defaultdict(lambda: defaultdict(list))

    for gw, dests in gateway_to_dests.items():
        cidrs = collapse_to_cidrs(dests)
        ip_to_cidr = {}
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            for d in dests:
                try:
                    if ipaddress.ip_address(d) in net:
                        ip_to_cidr[d] = cidr
                except ValueError:
                    pass
        for dest_ip in dests:
            cidr = ip_to_cidr.get(dest_ip, dest_ip + "/32")
            cidr_tree[cidr][gw].append({
                "dest":      dest_ip,
                "hostname":  all_data[dest_ip]["hostname"],
                "hop_count": all_data[dest_ip]["hop_count"],
            })

    for dest_ip in no_gateway:
        cidr_tree[dest_ip + "/32"]["(no traceroute)"].append({
            "dest":      dest_ip,
            "hostname":  all_data[dest_ip]["hostname"],
            "hop_count": all_data[dest_ip]["hop_count"],
        })

    return _merge_sibling_cidrs(cidr_tree)


def _merge_sibling_cidrs(cidr_tree):
    gw_key_to_cidrs = defaultdict(list)
    for cidr, gw_dict in cidr_tree.items():
        gw_key_to_cidrs[frozenset(gw_dict.keys())].append(cidr)

    new_tree = defaultdict(lambda: defaultdict(list))
    for _gw_set, cidrs in gw_key_to_cidrs.items():
        all_ips = [e["dest"]
                   for cidr in cidrs
                   for entries in cidr_tree[cidr].values()
                   for e in entries]

        merged_cidrs = collapse_to_cidrs(list(set(all_ips)))
        ip_to_merged = {}
        for mc in merged_cidrs:
            net = ipaddress.ip_network(mc, strict=False)
            for ip in all_ips:
                try:
                    if ipaddress.ip_address(ip) in net:
                        ip_to_merged[ip] = mc
                except ValueError:
                    pass

        for cidr in cidrs:
            for gw, entries in cidr_tree[cidr].items():
                for e in entries:
                    mc = ip_to_merged.get(e["dest"], e["dest"] + "/32")
                    new_tree[mc][gw].append(e)

    return new_tree


def build_gateway_summary(cidr_tree):
    gw_info = defaultdict(lambda: {"cidrs": set(), "dest_count": 0})
    for cidr, gw_dict in cidr_tree.items():
        for gw, entries in gw_dict.items():
            gw_info[gw]["cidrs"].add(cidr)
            gw_info[gw]["dest_count"] += len(entries)

    result = {}
    for gw, info in gw_info.items():
        cidrs = sorted(info["cidrs"],
                       key=lambda c: (ipaddress.ip_network(c, strict=False).network_address,
                                      ipaddress.ip_network(c, strict=False).prefixlen))
        supernet = find_tightest_supernet(cidrs)
        result[gw] = {
            "cidrs":           cidrs,
            "dest_count":      info["dest_count"],
            "common_supernet": supernet,
        }
    return result


# ================================================================
# Sort helpers
# ================================================================
def _net_sort(c):
    n = ipaddress.ip_network(c, strict=False)
    return (n.version, n.network_address, n.prefixlen)

def _gw_key(g):
    try:    return ipaddress.ip_address(g)
    except: return ipaddress.ip_address("0.0.0.0")

def _gw_sort(g):
    if g == "(no traceroute)":
        return (1, ipaddress.ip_address("255.255.255.255"))
    try:    return (0, ipaddress.ip_address(g))
    except: return (0, ipaddress.ip_address("0.0.0.0"))


# ================================================================
# Banner
# ================================================================
def print_banner(files, scan_meta, all_data, cidr_tree, gw_summary, uc, u):
    W = 62
    h = S("dbl_h", u); tl = S("dbl_tl", u); tr = S("dbl_tr", u)
    bl = S("dbl_bl", u); br = S("dbl_br", u)
    lm = S("dbl_lm", u); rm = S("dbl_rm", u)
    vb = "\u2551" if u else "|"

    def row(text, center=False):
        vis = len(_strip_ansi(text))
        inner = W - 4
        pad = max(0, inner - vis)
        if center:
            lp = pad // 2; rp = pad - lp
            _p(_cf("cyan", vb, uc) + "  " + " "*lp + text + " "*rp + "  " + _cf("cyan", vb, uc))
        else:
            _p(_cf("cyan", vb, uc) + "  " + text + " "*pad + "  " + _cf("cyan", vb, uc))

    def divider():
        _p(_cf("cyan", lm + h*(W-2) + rm, uc))

    _p(_cf("cyan", tl + h*(W-2) + tr, uc))

    # Title
    title_text = _c("yellow", "  NMAP TRACEROUTE INVESTIGATOR  ", uc)
    row(title_text, center=True)
    divider()

    # Scan info
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    row(_c("white", f"  Analyzed   : {now}", uc))
    for f in files:
        row(_cf("blue", f"  File       : {Path(f).name}", uc))
    if scan_meta.get("startstr"):
        row(_cf("blue", f"  Scan Date  : {scan_meta['startstr']}", uc))
    divider()

    # Stats row
    total_hosts   = len(all_data)
    total_gw      = len([g for g in gw_summary if g != "(no traceroute)"])
    total_cidrs   = len(cidr_tree)
    total_subnets = sum(1 for c in cidr_tree if ipaddress.ip_network(c,strict=False).prefixlen < 32)
    no_trace      = sum(1 for v in all_data.values() if not v["hop_count"])

    stat = (
        _cb("black", "bg_green",   f"HOSTS  {total_hosts}", uc)  + "  " +
        _cb("black", "bg_cyan",    f"GATEWAYS  {total_gw}", uc)  + "  " +
        _cb("black", "bg_yellow",  f"CIDRs  {total_cidrs}", uc)  + "  " +
        _cb("black", "bg_magenta", f"SUBNETS  {total_subnets}", uc)
    )
    row(stat, center=True)

    if no_trace:
        row(_cf("red", f"  {S('warn',u)}  {no_trace} host(s) have no traceroute data", uc))

    _p(_cf("cyan", bl + h*(W-2) + br, uc))
    _p()


# ================================================================
# Section header helper
# ================================================================
def _section(title, u, uc):
    h = S("sgl_h", u)
    ar = S("arrow_r", u)
    _p()
    _p(_c("cyan", f" {ar} {title}", uc))
    _p(_cf("cyan", "  " + h * 56, uc))
    _p()


# ================================================================
# Print: CIDR tree
# ================================================================
def print_report(cidr_tree, uc, u):
    _section("CIDR TREE  —  Destination Groups by Last-Hop Gateway", u, uc)

    tee  = S("tee",  u)
    cor  = S("cor",  u)
    pipe = S("pipe", u)
    diam = S("diamond", u)
    h_ic = S("host_icon", u)
    c_ic = S("cidr_icon", u)

    for cidr in sorted(cidr_tree.keys(), key=_net_sort):
        net   = ipaddress.ip_network(cidr, strict=False)
        label = cidr_display(cidr)
        count = sum(len(v) for v in cidr_tree[cidr].values())
        is_sub = net.prefixlen < net.max_prefixlen

        # CIDR / IP header
        if is_sub:
            prefix_badge = _cb("black", "bg_yellow", f"/{net.prefixlen}", uc)
            host_badge   = _cb("black", "bg_green",  f"{count} hosts", uc)
            hdr = (
                _c("yellow", f" {c_ic} {label}", uc)
                + "  " + prefix_badge + "  " + host_badge
            )
        else:
            hdr = _c("yellow", f" {c_ic} {label}", uc) + "  " + _cb("black", "bg_blue", "single", uc)
        _p(hdr)

        gateways = sorted(cidr_tree[cidr].keys(), key=_gw_key)
        for gi, gw in enumerate(gateways):
            last_gw   = (gi == len(gateways) - 1)
            gw_conn   = cor if last_gw else tee
            gw_indent = "    " if last_gw else (pipe + "   ")

            gw_line = (
                _cf("cyan", f"    {gw_conn} ", uc)
                + _cb("black", "bg_magenta", "GW", uc)
                + "  "
                + _c("magenta", gw, uc)
            )
            _p(gw_line)

            entries = sorted(cidr_tree[cidr][gw],
                             key=lambda x: ipaddress.ip_address(x["dest"]))
            for di, e in enumerate(entries):
                last_d = (di == len(entries) - 1)
                d_conn = cor if last_d else tee
                hn     = _dim(f"  ({e['hostname']})", uc) if e["hostname"] else ""
                hops   = _dim(f"  [{e['hop_count']} hops]", uc) if e["hop_count"] else ""
                dest_colored = _c("green", e["dest"], uc)
                _p(f"    {gw_indent} {_cf('cyan', d_conn, uc)} {_cf('white', h_ic, uc)} {dest_colored}{hn}{hops}")

        _p()


# ================================================================
# Print: gateway summary
# ================================================================
def print_gateway_summary(gw_summary, uc, u):
    _section("GATEWAY SUMMARY  —  Subnet Ownership & Common Supernets", u, uc)

    tee  = S("tee",  u)
    cor  = S("cor",  u)
    pipe = S("pipe", u)
    chk  = S("check", u)
    crs  = S("cross", u)
    net_ic = S("net_icon", u)
    h    = S("sgl_h", u)

    gateways = sorted(gw_summary.keys(), key=_gw_sort)

    for idx, gw in enumerate(gateways):
        info     = gw_summary[gw]
        cidrs    = info["cidrs"]
        count    = info["dest_count"]
        supernet = info["common_supernet"]
        n_sub    = len(cidrs)

        # Gateway header badge row
        sub_badge  = _cb("black", "bg_cyan",    f"{n_sub} subnet{'s' if n_sub>1 else ''}", uc)
        host_badge = _cb("black", "bg_green",   f"{count} host{'s' if count>1 else ''}",   uc)

        if gw == "(no traceroute)":
            gw_label = _c("red", gw, uc)
        else:
            gw_label = _c("magenta", gw, uc)

        _p(f" {_cf('cyan', net_ic, uc)} {gw_label}  {sub_badge}  {host_badge}")

        # Supernet line
        if supernet and supernet not in cidrs:
            sn_display = _c("cyan", supernet, uc)
            _p(f"    {tee} {_cf('green', chk, uc)}  Common Supernet  {_cf('cyan', h*3, uc)}  {sn_display}")
        elif len(cidrs) == 1:
            _p(f"    {tee} {_cf('yellow', crs, uc)}  Single CIDR  {_dim('(no supernet needed)', uc)}")
        else:
            _p(f"    {tee} {_cf('red', crs, uc)}  {_cf('red', 'Non-contiguous', uc)}  {_dim('(no common supernet)', uc)}")

        # Subnet list
        for ci, cidr in enumerate(cidrs):
            last_c = (ci == len(cidrs) - 1)
            conn   = cor if last_c else tee
            net    = ipaddress.ip_network(cidr, strict=False)
            label  = cidr_display(cidr)
            is_sub = net.prefixlen < net.max_prefixlen

            if is_sub:
                cidr_str = _c("yellow", label, uc) + _dim(f"  (/{net.prefixlen})", uc)
            else:
                cidr_str = _c("yellow", label, uc) + _dim("  (/32 host)", uc)

            # Count hosts in this cidr
            host_ct = sum(
                len(entries)
                for c2, gw_dict in [(cidr, gw_summary)]  # placeholder
                for entries in [info["cidrs"]]
            )
            _p(f"    {conn} {_cf('white', cidr_str, uc)}")

        # Separator between gateways
        if idx < len(gateways) - 1:
            _p(_cf("cyan", f"    {h*50}", uc))
        _p()

    # Final border
    _p(_cf("cyan", "  " + S("dbl_h", u) * 56, uc))
    _p()


# ================================================================
# Stats footer
# ================================================================
def print_footer(all_data, cidr_tree, gw_summary, uc, u):
    h   = S("dbl_h", u)
    tl  = S("dbl_tl", u); tr = S("dbl_tr", u)
    bl  = S("dbl_bl", u); br = S("dbl_br", u)
    lm  = S("dbl_lm", u); rm = S("dbl_rm", u)
    vb  = "\u2551" if u else "|"
    W   = 62

    def row(label, val, color="white"):
        inner = W - 4
        lbl = _dim(label, uc)
        v   = _c(color, str(val), uc)
        vis_lbl = len(_strip_ansi(lbl))
        vis_v   = len(_strip_ansi(v))
        dots = max(1, inner - vis_lbl - vis_v - 2)
        _p(_cf("cyan", vb, uc) + "  " + lbl + _dim("."*dots, uc) + v + "  " + _cf("cyan", vb, uc))

    def divider():
        _p(_cf("cyan", lm + h*(W-2) + rm, uc))

    total_hosts     = len(all_data)
    total_gw        = len([g for g in gw_summary if g != "(no traceroute)"])
    total_cidrs     = len(cidr_tree)
    total_subnets   = sum(1 for c in cidr_tree if ipaddress.ip_network(c,strict=False).prefixlen < 32)
    no_trace        = sum(1 for v in all_data.values() if not v["hop_count"])
    gw_with_super   = sum(1 for g in gw_summary.values() if g["common_supernet"] and g["common_supernet"] not in g["cidrs"])

    _p(_cf("cyan", tl + h*(W-2) + tr, uc))
    title = _c("yellow", "SCAN STATISTICS", uc)
    vis = len(_strip_ansi(title))
    inner = W - 4
    lp = (inner - vis) // 2; rp = inner - vis - lp
    _p(_cf("cyan", vb, uc) + "  " + " "*lp + title + " "*rp + "  " + _cf("cyan", vb, uc))
    divider()

    row("Total destination hosts",          total_hosts,   "green")
    row("Active gateways",                  total_gw,      "magenta")
    row("CIDR groups",                      total_cidrs,   "yellow")
    row("Subnet groups  (prefix < /32)",    total_subnets, "cyan")
    row("Hosts with no traceroute data",    no_trace,      "red" if no_trace else "green")
    row("Gateways with common supernet",    gw_with_super, "cyan")

    _p(_cf("cyan", bl + h*(W-2) + br, uc))
    _p()


# ================================================================
# Entry point
# ================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Nmap XML Traceroute Investigator - Rich CIDR tree + gateway summary"
    )
    parser.add_argument("xml_files", nargs="+", metavar="NMAP_XML")
    parser.add_argument("--no-color", action="store_true", default=False)
    parser.add_argument("--ascii",    action="store_true", default=False,
                        help="Force plain ASCII (auto on non-UTF-8 Windows consoles)")
    args = parser.parse_args()

    uc = HAS_COLOR and not args.no_color
    u  = _UNICODE_TERM and not args.ascii

    all_data  = {}
    scan_meta = {}

    for xml_path_str in args.xml_files:
        xml_path = Path(xml_path_str)
        if not xml_path.exists():
            _p(f"[WARN] File not found: {xml_path}", file=sys.stderr)
            continue
        result = parse_nmap_xml(xml_path)
        parsed, meta = result
        all_data.update(parsed)
        scan_meta.update(meta)
        _p(_cf("cyan", f"  [+] Loaded {len(parsed)} hosts from {xml_path.name}", uc))

    if not all_data:
        _p("[ERROR] No hosts found.", file=sys.stderr)
        sys.exit(1)

    _p()
    cidr_tree  = build_groups(all_data)
    gw_summary = build_gateway_summary(cidr_tree)

    print_banner(args.xml_files, scan_meta, all_data, cidr_tree, gw_summary, uc, u)
    print_report(cidr_tree, uc, u)
    print_gateway_summary(gw_summary, uc, u)
    print_footer(all_data, cidr_tree, gw_summary, uc, u)


if __name__ == "__main__":
    main()
