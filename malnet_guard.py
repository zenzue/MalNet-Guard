#!/usr/bin/env python3
"""
MalNet Guard — Advanced Cross‑Platform Malicious Network Connection Auditor
Author: w01f
License: MIT
Purpose: Help determine if a host may be malware‑infected or exfiltrating data.

Key features
- Cross‑platform (Windows, Linux, macOS) using psutil; optionally parses ss/netstat if present.
- Foreign address reputation checks (local blocklists + optional cloud APIs: AbuseIPDB, VirusTotal).
- Heuristics for exfiltration/suspicious ports, long‑lived outbound sessions, and unusual listeners.
- Hidden sockets/ports detector (Linux): inodes without owning process, orphan listeners.
- Output: human readable table + JSON (machine‑parsable) + exit codes.
- Designed as a lightweight "framework": rules.yaml drives thresholds and ports; plugins can be added.
"""
from __future__ import annotations

import argparse
from dotenv import load_dotenv
load_dotenv()

import dataclasses
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

try:
    import psutil
except Exception as e:
    psutil = None

__VERSION__ = "0.3.0"
__AUTHOR__  = "w01f"

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")

def safe_int(x: str, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def mask_ip(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            parts = ip.split(".")
            return ".".join(parts[:2] + ["x","x"])
        else:
            return ip[:8] + ":*:*"
    except Exception:
        return ip

def read_rules(path: str) -> Dict[str, Any]:
    import yaml  
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def load_default_rules() -> Dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    default = os.path.join(here, "rules.yaml")
    if os.path.exists(default):
        try:
            return read_rules(default)
        except Exception:
            pass
    return {
        "exfil": {"window_seconds": 120, "bytes_out_threshold": 50_000_000, "suspect_ports": [20,21,23,69,445,3389,5900,6667,31337]},
        "listen_suspicious_ports": [23, 2323, 31337, 1337, 4444, 5555, 6666, 6697],
        "blocklist_ips": [],
        "allowlist_ips": [],
        "tag_ports": {"ssh":[22,2222], "rdp":[3389], "vnc":[5900,5901], "db":[1433,1521,3306,5432,27017]},
    }

def human_bytes(n: int) -> str:
    for unit in ["B","KB","MB","GB","TB"]:
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.0f} PB"

@dataclasses.dataclass
class ConnRecord:
    pid: Optional[int]
    laddr: Tuple[str, int]
    raddr: Tuple[str, int]
    status: str
    proto: str
    exe: Optional[str]
    proc_name: Optional[str]
    uid: Optional[int] = None


class ConnectionCollector:
    def __init__(self, use_tools_first: bool = False):
        self.use_tools_first = use_tools_first

    def collect(self) -> List[ConnRecord]:
        if self.use_tools_first or psutil is None:
            recs = self._collect_with_tools()
            if recs:
                return recs
        if psutil is not None:
            return self._collect_with_psutil()
        return self._collect_with_tools()

    def _collect_with_psutil(self) -> List[ConnRecord]:
        results: List[ConnRecord] = []
        kind = "inet"
        for c in psutil.net_connections(kind=kind):
            laddr = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
            raddr = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            proc_name = exe = None
            try:
                if c.pid:
                    p = psutil.Process(c.pid)
                    proc_name = p.name()
                    exe = p.exe()
            except Exception:
                pass
            status = getattr(c, "status", "") or ""
            results.append(ConnRecord(c.pid, laddr, raddr, status, proto, exe, proc_name))
        return results

    def _collect_with_tools(self) -> List[ConnRecord]:
        cmds = []
        if which("ss"):
            cmds.append(("ss", "ss -tunp"))
        if which("netstat"):
            if platform.system().lower() == "windows":
                cmds.append(("netstat","netstat -anob"))
            else:
                cmds.append(("netstat","netstat -tunp"))
        for name, cmd in cmds:
            try:
                out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=10)
                recs = self._parse_tool_output(name, out)
                if recs:
                    return recs
            except Exception:
                continue
        return []

    def _parse_tool_output(self, tool: str, output: str) -> List[ConnRecord]:
        recs: List[ConnRecord] = []
        lines = output.splitlines()
        for line in lines:
            if tool == "ss":
                if not line.startswith(("tcp","udp")):
                    continue
                parts = line.split()
                if len(parts) < 5: 
                    continue
                proto, status = parts[0], parts[1] if parts[1].isalpha() else ""
                l, r = parts[-3], parts[-2]
                l_ip, l_port = split_hostport(l)
                r_ip, r_port = split_hostport(r)
                pid, pname = extract_pid_name(line)
                recs.append(ConnRecord(pid, (l_ip,l_port), (r_ip,r_port), status, proto, None, pname))
            else:
                if not line.strip() or line.startswith(("Proto","Active","(Not","  Proto")):
                    continue
                tokens = line.split()
                if tokens[0].lower() in ("tcp","udp","tcp4","tcp6","udp4","udp6"):
                    proto = "tcp" if tokens[0].lower().startswith("tcp") else "udp"
                    try:
                        l_ip,l_port = split_hostport(tokens[1])
                        r_ip,r_port = split_hostport(tokens[2])
                        status = tokens[3] if proto=="tcp" and len(tokens)>=4 else ""
                        recs.append(ConnRecord(None,(l_ip,l_port),(r_ip,r_port),status,proto,None,None))
                    except Exception:
                        continue
        return recs

def split_hostport(s: str) -> Tuple[str,int]:
    s = s.strip()
    if s.startswith("["):
        host, port = s.rsplit("]:",1)
        return host.strip("[]"), safe_int(port)
    if s.count(":") > 1 and not s.endswith("]"):
        host, port = s.rsplit(":",1)
        return host, safe_int(port)
    if ":" in s:
        host, port = s.rsplit(":",1)
        return host, safe_int(port)
    return s, 0

def extract_pid_name(s: str) -> Tuple[Optional[int], Optional[str]]:
    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', s)
    if m:
        return int(m.group(2)), m.group(1)
    m = re.search(r'"([^"]+)"\s*\[(\d+)\]', s)
    if m:
        return int(m.group(2)), m.group(1)
    return None, None

class Reputation:
    def __init__(self, rules: Dict[str, Any]):
        self.rules = rules
        self.allow = set(rules.get("allowlist_ips", []))
        self.block = set(rules.get("blocklist_ips", []))
        self.vt_key = os.getenv("VT_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")

    def local_label(self, ip: str) -> Tuple[str, int]:
        if ip in self.allow: return ("allowlist", -10)
        if ip in self.block: return ("blocklist", 100)
        if is_private_ip(ip): return ("private", -5)
        return ("unknown", 0)

    def remote_score(self, ip: str, timeout: float = 3.0) -> Tuple[str, int]:
        try:
            if self.abuseipdb_key:
                import urllib.request, json
                req = urllib.request.Request(
                    f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode())
                    score = int(data["data"].get("abuseConfidenceScore", 0))
                    return ("abuseipdb", score)
            if self.vt_key:
                import urllib.request, json, base64
                rid = ip
                req = urllib.request.Request(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{rid}",
                    headers={"x-apikey": self.vt_key},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode())
                    reps = data.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                    score = int(reps.get("malicious",0))*20 + int(reps.get("suspicious",0))*10
                    return ("virustotal", score)
        except Exception:
            pass
        return ("none", 0)

class Heuristics:
    def __init__(self, rules: Dict[str, Any], rep: Reputation):
        self.rules = rules
        self.rep = rep

    def score_conn(self, c: ConnRecord) -> Dict[str, Any]:
        risk = 0
        reasons: List[str] = []
        r_ip, r_port = c.raddr
        l_ip, l_port = c.laddr

        lbl, s = self.rep.local_label(r_ip)
        risk += s
        if lbl == "blocklist":
            reasons.append(f"remote_ip_in_blocklist({r_ip})")
        if lbl == "allowlist":
            reasons.append(f"remote_ip_in_allowlist({r_ip})")
        if lbl == "private":
            reasons.append("private_remote_ip")

        sus_ports = set(self.rules.get("exfil", {}).get("suspect_ports", [])) | set(self.rules.get("listen_suspicious_ports", []))
        if r_port in sus_ports and r_port not in (80,443):
            risk += 20
            reasons.append(f"suspicious_port:{r_port}")

        if c.proto == "tcp" and c.status in ("ESTAB","SYN_SENT"):
            risk += 5
            reasons.append(f"tcp_state:{c.status}")

        if c.raddr == ("",0) and l_port < 1024 and (c.pid or 0) > 0:
            try:
                if psutil:
                    p = psutil.Process(c.pid)
                    if p.uids().effective != 0:
                        risk += 10
                        reasons.append("nonroot_on_privileged_port")
            except Exception:
                pass

        if platform.system().lower() == "linux":
            if c.proc_name is None and c.pid is None and c.status in ("LISTEN",""):
                risk += 15
                reasons.append("orphan_listener_no_owner")

        return {"risk": max(risk,0), "reasons": reasons}

class ExfilMonitor:
    def __init__(self, rules: Dict[str, Any], window: Optional[int] = None):
        self.rules = rules
        self.window = window or int(rules.get("exfil",{}).get("window_seconds",120))

    def sample_bytes(self) -> Tuple[int,int]:
        try:
            import psutil
            io = psutil.net_io_counters(pernic=False)
            return int(io.bytes_sent), int(io.bytes_recv)
        except Exception:
            try:
                def rd(p):
                    with open(p,"r") as f: return int(f.read().strip())
                base = "/sys/class/net"
                tx = rx = 0
                for nic in os.listdir(base):
                    p = os.path.join(base, nic, "statistics")
                    if os.path.exists(p):
                        rx += rd(os.path.join(p,"rx_bytes"))
                        tx += rd(os.path.join(p,"tx_bytes"))
                return tx, rx
            except Exception:
                return (0,0)

    def run_window(self) -> Dict[str, Any]:
        start_tx, start_rx = self.sample_bytes()
        time.sleep(max(1, min(self.window, 10)))
        end_tx, end_rx = self.sample_bytes()
        return {
            "window_seconds": self.window,
            "bytes_sent_delta": max(0, end_tx - start_tx),
            "bytes_recv_delta": max(0, end_rx - start_rx),
        }

def linux_orphan_inodes_hint() -> List[int]:
    """Best‑effort: find listening TCP inodes not referenced by any /proc/*/fd.
    Requires /proc.
    """
    results: List[int] = []
    try:
        tcp_files = ["/proc/net/tcp","/proc/net/tcp6"]
        inodes = set()
        for f in tcp_files:
            if not os.path.exists(f): 
                continue
            with open(f,"r") as fh:
                next(fh)
                for line in fh:
                    cols = line.split()
                    st = cols[3]
                    if st == "0A":
                        inode = int(cols[9])
                        inodes.add(inode)
        referenced = set()
        for pid in filter(str.isdigit, os.listdir("/proc")):
            fd_dir = f"/proc/{pid}/fd"
            if not os.path.isdir(fd_dir):
                continue
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        target = os.readlink(os.path.join(fd_dir, fd))
                        m = re.match(r"socket:\[(\d+)\]", target)
                        if m:
                            referenced.add(int(m.group(1)))
                    except Exception:
                        continue
            except Exception:
                continue
        orphans = list(inodes - referenced)
        return sorted(orphans)[:50]
    except Exception:
        return results

def get_default_gateway() -> Optional[str]:
    """Best-effort default gateway detection across platforms."""
    try:
        if platform.system().lower() == "linux" and shutil.which("ip"):
            out = subprocess.check_output("ip route", shell=True, text=True, timeout=5)
            for line in out.splitlines():
                if line.startswith("default via "):
                    return line.split()[2]
    except Exception:
        pass
    try:
        if platform.system().lower() == "darwin" and shutil.which("route"):
            out = subprocess.check_output("route -n get default", shell=True, text=True, timeout=5)
            for line in out.splitlines():
                if "gateway:" in line:
                    return line.split()[-1]
    except Exception:
        pass
    try:
        if platform.system().lower() == "windows" and shutil.which("route"):
            out = subprocess.check_output("route print 0.0.0.0", shell=True, text=True, timeout=5, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    cols = [c for c in line.split(" ") if c]
                    if len(cols) >= 4:
                        return cols[3]
    except Exception:
        pass
    return None

def get_arp_table() -> List[Tuple[str,str,str]]:
    """Return list of (ip, mac, iface_or_type)."""
    rows: List[Tuple[str,str,str]] = []
    try:
        if platform.system().lower() == "linux":
            if which("ip"):
                out = subprocess.check_output("ip neigh", shell=True, text=True, timeout=5)
                for ln in out.splitlines():
                    parts = ln.split()
                    if len(parts) >= 5 and parts[2] == "lladdr":
                        ip, mac = parts[0], parts[4]
                        dev = parts[-1] if "dev" in parts else ""
                        rows.append((ip, mac.lower(), dev))
            elif which("arp"):
                out = subprocess.check_output("arp -an", shell=True, text=True, timeout=5)
                rows += parse_arp_an(out)
        else:
            if which("arp"):
                out = subprocess.check_output("arp -a", shell=True, text=True, timeout=5)
                rows += parse_arp_an(out)
    except Exception:
        pass
    return rows

def parse_arp_an(output: str) -> List[Tuple[str,str,str]]:
    rows = []
    for ln in output.splitlines():
        m = re.search(r'\(([\d\.]+)\)\s+at\s+([0-9a-f:]{11,17})', ln, re.I)
        if m:
            ip = m.group(1)
            mac = m.group(2).lower()
            iface = ""
            m2 = re.search(r'on\s+([a-zA-Z0-9\.\-_:]+)', ln)
            if m2: iface = m2.group(1)
            rows.append((ip, mac, iface))
    return rows

def analyze_arp_spoof() -> Dict[str, Any]:
    gw = get_default_gateway()
    table = get_arp_table()
    mac_to_ips: Dict[str, List[str]] = {}
    ip_to_mac: Dict[str, str] = {}
    for ip, mac, iface in table:
        ip_to_mac[ip] = mac
        mac_to_ips.setdefault(mac, []).append(ip)

    findings: Dict[str, Any] = {
        "default_gateway": gw,
        "gateway_mac": ip_to_mac.get(gw) if gw else None,
        "arp_entries": [{"ip": ip, "mac": mac, "iface": iface} for ip, mac, iface in table],
        "duplicates": {mac: ips for mac, ips in mac_to_ips.items() if len(ips) >= 3},
        "conflicts": [],
        "suspected_spoof": False,
        "notes": []
    }

    if gw:
        gw_mac = ip_to_mac.get(gw)
        if gw_mac and len(mac_to_ips.get(gw_mac, [])) >= 8:
            findings["suspected_spoof"] = True
            findings["notes"].append("Gateway MAC maps to many IPs (possible ARP proxy/spoof).")
        if gw_mac is None:
            findings["suspected_spoof"] = True
            findings["notes"].append("Gateway has no ARP entry (possible ARP blocking).")
    for mac, ips in mac_to_ips.items():
        if len(ips) >= 10:
            findings["suspected_spoof"] = True
            findings["notes"].append(f"MAC {mac} claims {len(ips)} IPs (NetCut/mitm-style behavior).")

    return findings

def quick_connectivity_check() -> Dict[str, Any]:
    """Detect 'internet cut' symptoms: LAN ok but WAN blocked. Non-invasive TCP connects."""
    targets = [("1.1.1.1",53), ("8.8.8.8",53), ("9.9.9.9",53)]
    res = {"lan_ip_present": False, "gateway": get_default_gateway(), "wan_ok": False, "details": []}
    try:
        if psutil:
            for ifc, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if getattr(a, "family", None) == socket.AF_INET and a.address and not a.address.startswith("169.254."):
                        res["lan_ip_present"] = True
                        break
    except Exception:
        pass
    ok = False
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=2.0) as s:
                ok = True
                res["details"].append(f"tcp_connect_ok:{host}:{port}")
                break
        except Exception as e:
            res["details"].append(f"tcp_connect_fail:{host}:{port}:{type(e).__name__}")
    res["wan_ok"] = ok
    return res

class ShodanClient:
    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key

    def host(self, ip: str, timeout: float = 4.0) -> Dict[str, Any]:
        if not self.api_key:
            return {}
        try:
            import urllib.request, json
            req = urllib.request.Request(f"https://api.shodan.io/shodan/host/{ip}?key={self.api_key}")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return {}

class PluginResult(dict):
    """Simple container for plugin outputs."""
    pass

class PluginBase:
    name = "base"
    def __init__(self, rules: Dict[str, Any]): self.rules = rules
    def enabled(self) -> bool: return self.rules.get("plugins", {}).get(self.name, {}).get("enabled", True)
    def run(self, context: Dict[str, Any]) -> PluginResult: return PluginResult()

def load_plugins(rules: Dict[str, Any]) -> List[PluginBase]:
    plugins: List[PluginBase] = []
    plug_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
    if not os.path.isdir(plug_dir):
        return plugins
    sys.path.insert(0, plug_dir)
    for fname in os.listdir(plug_dir):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        modname = fname[:-3]
        try:
            mod = __import__(modname)
            if hasattr(mod, "Plugin") and issubclass(mod.Plugin, PluginBase):
                p = mod.Plugin(rules)
                if p.enabled():
                    plugins.append(p)
        except Exception:
            continue
    return plugins

def run_plugins(plugins: List[PluginBase], context: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for p in plugins:
        try:
            res = p.run(context) or {}
            out[p.name] = res
        except Exception as e:
            out[p.name] = {"error": str(e)}
    return out


def print_table(rows: List[Dict[str, Any]]) -> None:
    headers = ["risk","proto","laddr","raddr","pid","proc","status","reasons"]
    print("\n=== MalNet Guard Report ===")
    print("time:", now_iso(), " version:", __VERSION__)
    print("-"*120)
    print("{:>4} {:<4} {:<22} {:<22} {:>6} {:<18} {:<10} {}".format(*headers))
    print("-"*120)
    for r in rows:
        print("{:>4} {:<4} {:<22} {:<22} {:>6} {:<18} {:<10} {}".format(
            r["risk"],
            r.get("proto",""),
            r.get("laddr",""),
            r.get("raddr",""),
            r.get("pid",""),
            (r.get("proc","") or "")[:18],
            r.get("status",""),
            ",".join(r.get("reasons",[]))[:200],
        ))
    print("-"*120)

def save_json(path: str, data: Any) -> None:
    with open(path,"w",encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def detect_arp_spoof() -> Dict[str, Any]:
    """Detect duplicate IP->MAC entries (possible ARP spoof)."""
    suspects = []
    try:
        entries = {}
        if platform.system().lower() == "linux":
            with open("/proc/net/arp") as f:
                next(f)
                for line in f:
                    ip, hw, flags, mac, mask, dev = line.split()
                    if mac != "00:00:00:00:00:00":
                        if ip in entries and entries[ip] != mac:
                            suspects.append({"ip": ip, "macs": [entries[ip], mac]})
                        entries[ip] = mac
        elif platform.system().lower() == "windows":
            out = subprocess.check_output("arp -a", shell=True, text=True)
            for l in out.splitlines():
                if "-" in l and "." in l:
                    parts = l.split()
                    if len(parts) >= 2:
                        ip, mac = parts[0], parts[1]
                        if ip in entries and entries[ip] != mac:
                            suspects.append({"ip": ip, "macs": [entries[ip], mac]})
                        entries[ip] = mac
        else:
            out = subprocess.check_output("arp -a", shell=True, text=True)
            for l in out.splitlines():
                if "at" in l and "(" not in l:
                    parts = l.split()
                    if len(parts) >= 3:
                        ip, mac = parts[1].strip("()"), parts[3]
                        if ip in entries and entries[ip] != mac:
                            suspects.append({"ip": ip, "macs": [entries[ip], mac]})
                        entries[ip] = mac
    except Exception as e:
        return {"error": str(e), "suspects": []}
    return {"suspects": suspects}

def shodan_lookup(ip: str) -> Dict[str, Any]:
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        return {}
    try:
        import urllib.request, json
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}



def main():
    if load_dotenv:
        try:
            from dotenv import load_dotenv as _ld
            _ld(dotenv_path=os.getenv('DOTENV_PATH') or '.env')
        except Exception:
            pass
    p = argparse.ArgumentParser(description="MalNet Guard — malicious network connection auditor via w01f")
    p.add_argument("--arp-check", action="store_true", help="scan ARP table for spoof/NetCut behavior and show attacker MAC hints")
    p.add_argument("--shodan", action="store_true", help="use SHODAN_API_KEY from .env to enrich remote IPs")
    p.add_argument("--rules", help="rules.yaml path (thresholds, lists)", default="rules.yaml")
    p.add_argument("--use-tools-first", action="store_true", help="prefer ss/netstat parsing first")
    p.add_argument("--cloud-reputation", action="store_true", help="enable AbuseIPDB or VirusTotal lookups (requires env keys)")
    p.add_argument("--json-out", default=None, help="write full JSON report to this path")
    p.add_argument("--top", type=int, default=30, help="show only top N risky connections")
    p.add_argument("--include-private", action="store_true", help="include connections to private IPs in output")
    p.add_argument("--exfil-check", action="store_true", help="run a short exfil window sampler")
    p.add_argument("--orphan-check", action="store_true", help="Linux: attempt to find orphan listening sockets")
    args = p.parse_args()

    try:
        rules = load_default_rules()
        if args.rules and os.path.exists(args.rules):
            try:
                r2 = read_rules(args.rules)
                rules.update(r2 or {})
            except Exception:
                pass
    except Exception as e:
        print("Failed to load rules:", e, file=sys.stderr)
        rules = load_default_rules()

    coll = ConnectionCollector(use_tools_first=args.use_tools_first)
    rep = Reputation(rules)
    heur = Heuristics(rules, rep)

    conns = coll.collect()
    rows = []
    for c in conns:
        if c.raddr and c.raddr[0] and not args.include_private and is_private_ip(c.raddr[0]):
            pass
        s = heur.score_conn(c)
        risk = s["risk"]
        reasons = s["reasons"]
        if args.cloud_reputation and c.raddr and c.raddr[0]:
            src, score = rep.remote_score(c.raddr[0])
            if score:
                risk += min(100, score)
                reasons.append(f"{src}_score:{score}")
        if args.shodan and c.raddr and c.raddr[0]:
            sh = ShodanClient(os.getenv("SHODAN_API_KEY")).host(c.raddr[0])
            if sh:
                if sh.get("tags"): reasons.append("shodan_tags:"+",".join(sh.get("tags", [])[:3]))
                if sh.get("ports"): reasons.append("shodan_open_ports:"+",".join(map(str, sh.get("ports", [])[:5])))
        rows.append({
            "risk": risk,
            "proto": c.proto,
            "laddr": f"{c.laddr[0]}:{c.laddr[1]}",
            "raddr": f"{c.raddr[0]}:{c.raddr[1]}",
            "pid": c.pid or 0,
            "proc": c.proc_name or "",
            "status": c.status,
            "reasons": reasons,
        })

    rows.sort(key=lambda r: r["risk"], reverse=True)
    if args.top:
        rows = rows[:args.top]

    print_table(rows)

    report: Dict[str, Any] = {
        "meta": {"time": now_iso(), "version": __VERSION__, "author": __AUTHOR__},
        "rows": rows,
        "platform": platform.platform(),
    }

    if args.arp_check:
        arp = analyze_arp_spoof()
        report["arp_analysis"] = arp
        print("\n[ARP Analysis] gateway:", arp.get("default_gateway"), " mac:", arp.get("gateway_mac"))
        if arp.get("duplicates"):
            print("MACs claiming many IPs:", {k: len(v) for k,v in arp["duplicates"].items()})
        if arp.get("suspected_spoof"):
            print("ARP SPOOF SUSPECTED:", "; ".join(arp.get("notes",[])))
    if args.exfil_check:
        ex = ExfilMonitor(rules).run_window()
        report["exfil_window"] = ex
        print("\n[Exfil Window] {}s  sent:{}  recv:{}".format(
            ex["window_seconds"], human_bytes(ex["bytes_sent_delta"]), human_bytes(ex["bytes_recv_delta"]))
        )

    if args.orphan_check and platform.system().lower() == "linux":
        orphans = linux_orphan_inodes_hint()
        report["linux_orphan_listen_inodes"] = orphans
        if orphans:
            print(f"\n[Hidden/Orphan listeners] inodes without owning process: {len(orphans)} (first 10 shown)")
            print(orphans[:10])

    ic = quick_connectivity_check()
    report["connectivity"] = ic
    if ic.get("lan_ip_present") and not ic.get("wan_ok"):
        print("\n[Connectivity] LAN up but WAN blocked — possible NetCut/ARP disruption.")
    plugins = load_plugins(rules)
    plugin_ctx = {"rows": rows, "report": report, "rules": rules}
    report["plugins"] = run_plugins(plugins, plugin_ctx)

    if args.json_out:
        save_json(args.json_out, report)

    risky = [r for r in rows if r["risk"] >= 50]
    if report.get("arp_analysis",{}).get("suspected_spoof"):
        risky.append({"risk": 80})
    for pn, pres in report.get("plugins", {}).items():
        if isinstance(pres, dict) and pres.get("critical"):
            risky.append({"risk": 80})
    sys.exit(2 if risky else 0)

if __name__ == "__main__":
    main()
