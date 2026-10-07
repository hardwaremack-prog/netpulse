#!/usr/bin/env python3
"""
NetPulse - hybrid network monitor
  * Monitor mode : live UP / DOWN board with counts for a list of IPs or hostnames
                   (import from Excel .xlsx, CSV, or paste)
  * Plotter mode : PingPlotter-style latency-over-time graphs, packet-loss markers,
                   hop-by-hop route tracing, multi-target summary graphs

  * PingInfoView-style extras: TCP port pings (host:port), success/fail counts and
                   streaks, last success/failure, TTL, reply IP, MAC address, alert
                   commands, auto-saved reports (HTML/CSV/XML/TXT), command-line reports

Run:   python netpulse.py            -> opens http://127.0.0.1:8790 in your browser
       python netpulse.py --lan      -> also reachable from other PCs on your network
       python netpulse.py --load hosts.xlsx --report status.html   (no window)
       python netpulse.py --help     -> every option

Needs only Python 3.8+ (no extra packages). Works on Windows, macOS and Linux.
"""
import argparse, array, bisect, collections, csv, io, ipaddress, json, os, platform, re, shutil
import socket, subprocess, sys, threading, time, webbrowser, zipfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(APP_DIR, "netpulse_data.json")
SYSTEM = platform.system()
IS_WIN = SYSTEM == "Windows"
IS_MAC = SYSTEM == "Darwin"
MAX_SAMPLES = 21600          # per host (6 hours at 1 s, 12 hours at 2 s)
MAX_HOSTS = 2000

SETTINGS = {"interval": 2.0, "timeout": 1000, "down_after": 2,
            "warn_ms": 150, "warn_loss": 10, "paused": False,
            "size": 32, "df": False,
            "cmd_down": "", "cmd_up": "",
            "autosave_min": 0, "autosave_fmt": "html", "autosave_dir": "", "autosave_stamp": True}
LOCAL_ONLY = ("cmd_down", "cmd_up", "autosave_dir")   # only changeable from this computer
LOCK = threading.RLock()
HOSTS = {}                                   # id -> Host (insertion ordered)
EVENTS = collections.deque(maxlen=300)
_next_id = [1]
POOL = ThreadPoolExecutor(max_workers=128)
PING_OK = bool(shutil.which("ping"))
ARP = {}                                     # ip -> MAC
LAN_MODE = [False]
AUTOSAVE = {"next": 0, "last": None, "last_file": "", "error": ""}

TIME_RE = re.compile(r"[=<]\s*([\d.,]+)\s*ms", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TTL_RE = re.compile(r"ttl[=:]\s*(\d+)", re.I)
FROM_RE = re.compile(r"(?:from|de|von)\s+(?:[^\s(]+\s+\()?\[?([0-9a-fA-F.:]+?)\]?\)?[:\s]", re.I)
PORT_RE = re.compile(r"^(?:\[([0-9a-fA-F:.]+)\]|([^\s:\[\]]+)):(\d{1,5})$")


def split_port(addr):
    """'host:80' or '[::1]:80' -> ('host', 80). Plain hosts and IPv6 -> (addr, None)."""
    m = PORT_RE.match(addr or "")
    if m and 0 < int(m.group(3)) < 65536:
        return (m.group(1) or m.group(2)), int(m.group(3))
    return addr, None


# ----------------------------------------------------------------- ping engine
def _run(cmd, timeout):
    kw = {"creationflags": 0x08000000} if IS_WIN else {}      # no console flash on Windows
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, **kw)
        return p.returncode, p.stdout.decode(errors="replace")
    except Exception:
        return -1, ""


def ping_cmd(addr, timeout_ms, ttl=None, size=None, df=False):
    timeout_ms = int(timeout_ms)
    v6 = ":" in addr
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms)] + (["-i", str(ttl)] if ttl else [])
        if size: cmd += ["-l", str(size)]
        if df and not v6: cmd += ["-f"]
    elif IS_MAC:
        if v6:
            return ["ping6", "-c", "1"] + (["-s", str(size)] if size else []) + [addr]
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms)] + (["-m", str(ttl)] if ttl else [])
        if size: cmd += ["-s", str(size)]
        if df: cmd += ["-D"]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000)))] + \
              (["-t", str(ttl)] if ttl else [])
        if size: cmd += ["-s", str(size)]
        if df: cmd += ["-M", "do"]
    return cmd + [addr]


def ping_once(addr, timeout_ms, size=None, df=False):
    """Return (ms or None, ttl, reply_ip, status_text)."""
    rc, out = _run(ping_cmd(addr, timeout_ms, size=size, df=df), timeout_ms / 1000 + 4)
    low = out.lower()
    m = TIME_RE.search(out)
    ok = "ttl=" in low or (rc == 0 and m and "unreachable" not in low and "expired" not in low)
    reply = None
    for line in out.splitlines()[1:]:
        if TIME_RE.search(line) or "unreachable" in line.lower() or "exceeded" in line.lower() \
                or "expired" in line.lower():
            fm = FROM_RE.search(line + " ")
            if fm:
                reply = fm.group(1).rstrip(":")
            break
    if not ok:
        if "unreachable" in low:
            st = "Unreachable"
        elif "expired" in low or "exceeded" in low:
            st = "TTL expired"
        elif "fragment" in low:
            st = "Needs fragmenting"
        elif rc == -1 and not out:
            st = "Ping failed to run"
        elif "could not find host" in low or "unknown host" in low or "name or service" in low:
            st = "Unknown host"
        else:
            st = "Timed out"
        return None, None, reply, st
    tm = TTL_RE.search(out)
    ms = 0.5
    if m:
        try:
            ms = max(0.1, float(m.group(1).replace(",", ".")))
        except ValueError:
            pass
    return ms, (int(tm.group(1)) if tm else None), reply, "Succeeded"


def tcp_once(host, port, timeout_ms):
    """TCP 'ping': time to open a connection. Returns (ms or None, None, ip, status)."""
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout=timeout_ms / 1000.0)
        ms = (time.perf_counter() - t0) * 1000
        ip = s.getpeername()[0]
        s.close()
        return max(0.05, ms), None, ip, "Port open"
    except socket.timeout:
        return None, None, None, "Timed out"
    except ConnectionRefusedError:
        return None, None, None, "Port closed"
    except socket.gaierror:
        return None, None, None, "Unknown host"
    except OSError as e:
        return None, None, None, (e.strerror or "Failed")[:40]


def ttl_probe(ip, ttl, timeout_ms=1500):
    """Ping with a limited TTL; return the IP of the router that answered (or None)."""
    rc, out = _run(ping_cmd(ip, timeout_ms, ttl), timeout_ms / 1000 + 4)
    lines = [l for l in out.splitlines() if l.strip()]
    for l in lines[1:]:
        if "statistic" in l.lower():
            break
        m = IPV4_RE.search(l)
        if m:
            return m.group(0)
    return None


MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")


def refresh_arp():
    """Read the computer's ARP table so devices on the local network show a MAC address."""
    table = {}
    try:
        if not IS_WIN and os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4:
                        table[p[0]] = p[3]
        else:
            _, out = _run(["arp", "-a"] if IS_WIN else ["arp", "-an"], 8)
            for line in out.splitlines():
                ipm, mm = IPV4_RE.search(line), MAC_RE.search(line)
                if ipm and mm:
                    table[ipm.group(0)] = mm.group(0)
    except Exception:
        return
    clean = {}
    for ip, mac in table.items():
        parts = re.split(r"[:-]", mac)
        if len(parts) != 6:
            continue
        mac = ":".join(p.zfill(2) for p in parts).upper()
        if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            continue
        clean[ip] = mac
    ARP.clear(); ARP.update(clean)


# ----------------------------------------------------------------- host model
class Host:
    def __init__(self, addr, name="", group="", parent=None, hop=None):
        self.id = str(_next_id[0]); _next_id[0] += 1
        self.addr, self.name, self.group = addr, name, group
        self.parent, self.hop = parent, hop
        self.host, self.port = split_port(addr)
        self.ts = array.array("d"); self.ms = array.array("d")
        self.status = "pending" if addr != "*" else "noreply"
        self.since = time.time()
        self.fails = 0
        self.busy = False
        self.ip = self.host if _is_ip(self.host) else ""
        self.trace, self.trace_msg = "idle", ""
        self.ok_count = self.fail_count = self.max_fails = 0
        self.last_ok = self.last_fail = self.last_ping = None
        self.ttl = self.reply = None
        self.last_status = ""

    def record(self, ms, ttl=None, reply=None, st=""):
        now = time.time()
        self.ts.append(now); self.ms.append(-1.0 if ms is None else ms)
        if len(self.ts) > MAX_SAMPLES + 600:
            del self.ts[:600]; del self.ms[:600]
        self.last_ping, self.last_status = now, st
        if reply:
            self.reply = reply
        if ms is None:
            self.fails += 1; self.fail_count += 1; self.last_fail = now
            self.max_fails = max(self.max_fails, self.fails)
            if self.status != "down" and self.fails >= SETTINGS["down_after"]:
                self.set_status("down", now)
        else:
            self.fails = 0; self.ok_count += 1; self.last_ok = now
            if ttl:
                self.ttl = ttl
            if self.status != "up":
                self.set_status("up", now)

    def set_status(self, st, now):
        old, dur = self.status, now - self.since
        self.status, self.since = st, now
        if self.parent:
            return
        if st == "down":
            log_event(self, "down", None if old == "pending" else dur)
        elif st == "up" and old == "down":
            log_event(self, "up", dur)

    def window(self, focus):
        i = bisect.bisect_left(self.ts, time.time() - focus) if focus > 0 else 0
        return self.ts[i:], self.ms[i:]

    def snapshot(self, focus):
        ts, ms = self.window(focus)
        n = len(ms)
        vals = [v for v in ms if v >= 0]
        total = self.ok_count + self.fail_count
        d = {"id": self.id, "addr": self.addr, "name": self.name, "group": self.group,
             "parent": self.parent, "hop": self.hop, "ip": self.ip, "status": self.status,
             "port": self.port, "since": self.since, "trace": self.trace,
             "trace_msg": self.trace_msg, "sent": n, "recv": len(vals),
             "loss": round(100.0 * (n - len(vals)) / n, 1) if n else 0.0,
             "cur": None, "avg": None, "min": None, "max": None, "jitter": None,
             "ok": self.ok_count, "fail": self.fail_count, "total": total,
             "fail_pct": round(100.0 * self.fail_count / total, 1) if total else 0.0,
             "in_row": self.fails, "max_row": self.max_fails,
             "last_ok": self.last_ok, "last_fail": self.last_fail, "last_ping": self.last_ping,
             "last_status": self.last_status, "ttl": self.ttl, "reply": self.reply,
             "mac": ARP.get(self.reply or self.ip or "", "")}
        if len(self.ms) and self.ms[-1] >= 0:
            d["cur"] = round(self.ms[-1], 2)
        if vals:
            d["avg"] = round(sum(vals) / len(vals), 2)
            d["min"] = round(min(vals), 2); d["max"] = round(max(vals), 2)
            if len(vals) > 1:
                d["jitter"] = round(sum(abs(vals[i] - vals[i - 1]) for i in range(1, len(vals)))
                                    / (len(vals) - 1), 2)
        d["spark"] = [round(v, 1) for v in self.ms[-60:]]
        if self.status in ("pending", "down", "noreply"):
            d["health"] = self.status
        elif d["loss"] >= SETTINGS["warn_loss"] or (d["avg"] or 0) >= SETTINGS["warn_ms"]:
            d["health"] = "degraded"
        else:
            d["health"] = "up"
        return d


def log_event(h, kind, dur):
    EVENTS.appendleft({"t": time.time(), "id": h.id, "name": h.name or h.addr,
                       "addr": h.addr, "kind": kind, "dur": dur})
    cmd = SETTINGS.get("cmd_down" if kind == "down" else "cmd_up", "")
    if cmd.strip():
        threading.Thread(target=run_hook, args=(cmd, h, kind, dur), daemon=True).start()


_UNSAFE = re.compile(r"[&|;<>^\"'`$%\\\r\n()!*?{}\[\]]")


def run_hook(cmd, h, kind, dur):
    """Run the user's own command when a device goes down or comes back."""
    vals = {"name": h.name or h.addr, "addr": h.addr, "ip": h.ip or h.host,
            "status": kind.upper(), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "group": h.group, "duration": str(int(dur or 0))}
    safe = {k: _UNSAFE.sub("", str(v)) for k, v in vals.items()}
    line = cmd
    for k, v in safe.items():
        line = line.replace("{%s}" % k, v)
    env = dict(os.environ, **{"NETPULSE_" + k.upper(): str(v) for k, v in vals.items()})
    kw = {"creationflags": 0x08000000} if IS_WIN else {}
    try:
        subprocess.Popen(line, shell=True, env=env, cwd=APP_DIR,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
    except Exception as e:
        print("Alert command failed:", e)


def probe(h):
    try:
        if not h.ip:
            try:
                h.ip = socket.gethostbyname(h.host)
            except Exception:
                pass
        if h.port:
            res = tcp_once(h.host, h.port, SETTINGS["timeout"])
        else:
            res = ping_once(h.host, SETTINGS["timeout"], SETTINGS.get("size") or None,
                            SETTINGS.get("df"))
        with LOCK:
            if h.id in HOSTS:
                h.record(*res)
    finally:
        h.busy = False


def monitor_loop():
    last_arp = 0
    while True:
        t0 = time.time()
        if not SETTINGS["paused"]:
            with LOCK:
                todo = [h for h in HOSTS.values() if not h.busy and h.addr != "*"]
                for h in todo:
                    h.busy = True
            for h in todo:
                POOL.submit(probe, h)
        if t0 - last_arp > 30:
            last_arp = t0
            POOL.submit(refresh_arp)
        try:
            autosave_tick()
        except Exception as e:
            AUTOSAVE["error"] = str(e)
        time.sleep(max(0.1, float(SETTINGS["interval"]) - (time.time() - t0)))


# ----------------------------------------------------------------- traceroute
def run_trace(hid):
    with LOCK:
        h = HOSTS.get(hid)
        if not h or h.trace == "running":
            return
        h.trace, h.trace_msg = "running", "Resolving..."
        addr = h.host
    try:
        ip = socket.gethostbyname(addr)
    except Exception:
        with LOCK:
            h.trace, h.trace_msg = "error", "Could not resolve " + addr
        return
    hops, reached = {}, None
    for attempt in range(3):
        missing = [t for t in range(1, (reached or 30) + 1) if t not in hops]
        if not missing:
            break
        with LOCK:
            h.trace_msg = "Tracing route... pass %d of 3" % (attempt + 1)
        with ThreadPoolExecutor(max_workers=len(missing)) as ex:
            for t, r in ex.map(lambda t: (t, ttl_probe(ip, t)), missing):
                if r:
                    hops[t] = r
        hit = [t for t, r in hops.items() if r == ip]
        if hit:
            reached = min(hit)
    last = (reached - 1) if reached else (max(hops) if hops else 0)
    new = []
    with LOCK:
        if hid not in HOSTS:
            return
        for k in [k for k, v in HOSTS.items() if v.parent == hid]:
            del HOSTS[k]
        for t in range(1, last + 1):
            a = hops.get(t)
            hh = Host(a or "*", "" if a else "no reply", h.group, parent=hid, hop=t)
            HOSTS[hh.id] = hh
            if a:
                new.append(hh)
        h.hop = last + 1 if reached else None
        h.trace = "done"
        h.trace_msg = ("%d hops" % (last + 1)) if reached else \
            "Destination didn't answer the trace - showing the hops that did"
    for hh in new:
        POOL.submit(_rdns, hh)


def _rdns(h):
    try:
        name = socket.gethostbyaddr(h.addr)[0]
        with LOCK:
            h.name = name
    except Exception:
        pass


def clear_trace(hid):
    with LOCK:
        for k in [k for k, v in HOSTS.items() if v.parent == hid]:
            del HOSTS[k]
        h = HOSTS.get(hid)
        if h:
            h.trace, h.trace_msg, h.hop = "idle", "", None


# ----------------------------------------------------------------- import (Excel / CSV / paste)
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$")
RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})\s*-\s*"
                      r"(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.)?(\d{1,3})$")
SINGLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,62}$")


def _is_ip(s):
    try:
        ipaddress.ip_address(s); return True
    except ValueError:
        return False


def is_target(s, loose=False):
    s = (s or "").strip()
    if not s:
        return False
    host, port = split_port(s)
    if port:
        return is_target(host, loose)
    if _is_ip(s) or RANGE_RE.match(s):
        return True
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False); return True
        except ValueError:
            return False
    if HOST_RE.match(s):
        parts = s.rstrip(".").split(".")
        return not parts[-1].isdigit()           # rejects "12.5", "300.1.1.1"
    return bool(loose and SINGLE_RE.match(s))


def expand(s):
    s = s.strip()
    host, port = split_port(s)
    if port:
        hp = ("[%s]" % "%s") if ":" in host else "%s"
        return [(hp % h) + ":" + str(port) for h in expand(host)]
    m = RANGE_RE.match(s)
    if m:
        a, b = int(m.group(2)), int(m.group(3))
        if a > b: a, b = b, a
        return [m.group(1) + str(i) for i in range(a, min(b, 255) + 1)][:1024]
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            if net.num_addresses == 1:
                return [str(net.network_address)]
            out = []
            for ip in net.hosts():
                out.append(str(ip))
                if len(out) >= 1024: break
            return out
        except ValueError:
            return []
    return [s.rstrip(".")]


def _col_index(ref):
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1


def read_xlsx(data):
    """Return [(sheet_name, rows)] using only the standard library."""
    M = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    shared = []
    if "xl/sharedStrings.xml" in names:
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).iter(M + "si"):
            shared.append("".join(t.text or "" for t in si.iter(M + "t")))
    sheets = []
    try:
        rels = {r.get("Id"): r.get("Target") for r in
                ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))}
        for s in ET.fromstring(z.read("xl/workbook.xml")).iter(M + "sheet"):
            tgt = rels.get(s.get(R + "id"), "")
            tgt = tgt.lstrip("/")
            if not tgt.startswith("xl/"):
                tgt = "xl/" + tgt
            if tgt in names:
                sheets.append((s.get("name", ""), tgt))
    except Exception:
        pass
    if not sheets:
        sheets = [("", n) for n in sorted(names) if re.match(r"xl/worksheets/sheet\d+\.xml$", n)]
    out = []
    for sname, path in sheets:
        rows = []
        for r in ET.fromstring(z.read(path)).iter(M + "row"):
            cells = {}
            for i, c in enumerate(r.findall(M + "c")):
                idx = _col_index(c.get("r")) if c.get("r") else i
                t, v = c.get("t"), c.find(M + "v")
                if t == "s" and v is not None:
                    val = shared[int(v.text)]
                elif t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter(M + "t"))
                else:
                    val = v.text if v is not None and v.text else ""
                    if re.fullmatch(r"-?\d+\.0", val):
                        val = val[:-2]
                cells[idx] = val
            rows.append([cells.get(i, "") for i in range(max(cells) + 1)] if cells else [])
        out.append((sname, rows))
    return out


def parse_text_rows(text):
    rows = []
    for line in text.splitlines():
        delim = next((d for d in ("\t", ",", ";") if d in line), None)
        if delim:
            rows.extend(csv.reader([line], delimiter=delim))
            continue
        toks = line.split()
        if not toks:
            continue
        i = next((j for j, t in enumerate(toks) if is_target(t)), None)
        if i is None and is_target(toks[0], loose=True):
            i = 0
        if i is None:
            rows.append(toks)
        else:
            rows.append([toks[i], " ".join(toks[:i] + toks[i + 1:])])
    return rows


ADDR_HDR = ("ip", "ips", "ip address", "ipaddress", "ip addr", "ip_address", "address", "host",
            "hostname", "host name", "host/ip", "ip/host", "device ip", "target", "fqdn", "dns")
NAME_HDR = ("name", "device", "description", "desc", "label", "hostname alias", "alias", "asset")
PORT_HDR = ("port", "tcp port", "tcp")
GROUP_HDR = ("group", "site", "location", "category", "building", "zone", "vlan", "area", "type")


def rows_to_entries(rows, default_group, loose=False):
    hdr, cols = None, {}
    for i, row in enumerate(rows[:6]):
        low = [str(c).strip().lower() for c in row]
        if any(c in ADDR_HDR or c.startswith("ip") for c in low) and \
                not any(is_target(str(c)) for c in row):
            hdr = i
            break
    if hdr is not None:
        for j, c in enumerate(rows[hdr]):
            l = str(c).strip().lower()
            if "port" not in cols and l in PORT_HDR:
                cols["port"] = j
            elif "addr" not in cols and (l in ADDR_HDR or l.startswith("ip")):
                cols["addr"] = j
            elif "name" not in cols and any(k in l for k in NAME_HDR):
                cols["name"] = j
            elif "group" not in cols and any(k in l for k in GROUP_HDR):
                cols["group"] = j
        body = rows[hdr + 1:]
    else:
        body = rows
    entries = []
    for row in body:
        cells = [str(c).strip() for c in row]
        if not any(cells):
            continue
        get = lambda k: cells[cols[k]] if k in cols and cols[k] < len(cells) else ""
        addr = ""
        ai = None
        if "addr" in cols:
            cand = get("addr")
            if cand and is_target(cand.split()[0], loose=True):
                addr, ai = cand.split()[0], cols["addr"]
        if not addr:
            for j, c in enumerate(cells):
                if c and is_target(c.split()[0]):
                    addr, ai = c.split()[0], j
                    break
        if not addr and loose and cells[0] and is_target(cells[0].split()[0], loose=True):
            addr, ai = cells[0].split()[0], 0
        if not addr:
            continue
        name = get("name")
        rest = cells[ai][len(addr):].strip(" -:,")
        if not name and rest:
            name = rest
        if not name:
            for j, c in enumerate(cells):
                if j != ai and c and j != cols.get("group") and not is_target(c):
                    name = c
                    break
        pt = get("port")
        if pt.isdigit() and 0 < int(pt) < 65536 and not split_port(addr)[1]:
            addr = ("[%s]" % addr if ":" in addr else addr) + ":" + pt
        entries.append((addr, name[:80], (get("group") or default_group)[:60]))
    return entries


def add_host(addr, name="", group=""):
    key = (addr.lower(), group)
    for h in HOSTS.values():
        if not h.parent and (h.addr.lower(), h.group) == key:
            return None
    if sum(1 for h in HOSTS.values() if not h.parent) >= MAX_HOSTS:
        return None
    h = Host(addr, name, group)
    HOSTS[h.id] = h
    return h


def import_payload(raw, filename, group, mode):
    fn = (filename or "").lower()
    if fn.endswith((".xlsx", ".xlsm")):
        try:
            sheets = read_xlsx(raw)
        except Exception:
            raise ValueError("That file couldn't be read as an Excel workbook.")
    elif fn.endswith(".xls"):
        raise ValueError("Old .xls files aren't supported. In Excel choose File > Save As > "
                         "Excel Workbook (.xlsx) or CSV, then import that.")
    else:
        for enc in ("utf-8-sig", "cp1252", "latin-1"):
            try:
                text = raw.decode(enc); break
            except UnicodeDecodeError:
                continue
        sheets = [("", parse_text_rows(text))]
    multi = sum(1 for _, r in sheets if r) > 1
    entries = []
    text_mode = not fn.endswith((".xlsx", ".xlsm"))
    for sname, rows in sheets:
        entries += rows_to_entries(rows, group or (sname if multi else ""), loose=text_mode)
    added = skipped = 0
    with LOCK:
        if mode == "replace":
            HOSTS.clear()
        for addr, name, g in entries:
            ips = expand(addr)
            for a in ips:
                if add_host(a, name if len(ips) == 1 else "", g):
                    added += 1
                else:
                    skipped += 1
    save()
    return {"added": added, "skipped": skipped, "found": len(entries)}


# ----------------------------------------------------------------- persistence
def save():
    if LAN_MODE[1:] and LAN_MODE[1]:        # --report runs never change the saved list
        return
    with LOCK:
        data = {"settings": {k: v for k, v in SETTINGS.items() if k != "paused"},
                "hosts": [{"addr": h.addr, "name": h.name, "group": h.group}
                          for h in HOSTS.values() if not h.parent]}
    try:
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, DATA_FILE)
    except Exception as e:
        print("Could not save list:", e)


def load():
    try:
        with open(DATA_FILE, encoding="utf-8") as f:
            data = json.load(f)
        for k, v in data.get("settings", {}).items():
            if k in SETTINGS and k != "paused":
                SETTINGS[k] = v
        with LOCK:
            for e in data.get("hosts", []):
                add_host(e.get("addr", ""), e.get("name", ""), e.get("group", ""))
    except FileNotFoundError:
        pass
    except Exception as e:
        print("Could not load saved list:", e)


# ----------------------------------------------------------------- API
def api_state(focus, local=True):
    with LOCK:
        hosts = [h.snapshot(focus) for h in HOSTS.values()]
        st = dict(SETTINGS)
        if not local:                        # don't show commands/folders to other devices
            for k in LOCAL_ONLY:
                st[k] = "(set on the host computer)" if st.get(k) else ""
        return {"now": time.time(), "hosts": hosts, "events": list(EVENTS)[:100],
                "settings": st, "platform": SYSTEM, "ping_ok": PING_OK, "local": local,
                "report_dir": report_dir() if local else "",
                "autosave": {"next": AUTOSAVE["next"], "last": AUTOSAVE["last"],
                             "file": os.path.basename(AUTOSAVE["last_file"] or ""),
                             "error": AUTOSAVE["error"]}}


def api_history(ids, focus, buckets):
    now = time.time()
    with LOCK:
        wins = {i: HOSTS[i].window(focus) for i in ids if i in HOSTS}
    if focus > 0:
        start = now - focus
    else:
        start = min((w[0][0] for w in wins.values() if len(w[0])), default=now - 60)
    span = max(1.0, now - start)
    bw = span / max(10, buckets)
    out = {}
    for hid, (ts, ms) in wins.items():
        agg = {}
        for t, v in zip(ts, ms):
            b = int((t - start) / bw)
            a = agg.get(b)
            if a is None:
                a = agg[b] = [0, 0.0, 1e18, -1.0, 0]
            a[0] += 1
            if v < 0:
                a[4] += 1
            else:
                a[1] += v
                if v < a[2]: a[2] = v
                if v > a[3]: a[3] = v
        rows = []
        for b in sorted(agg):
            n, s, mn, mx, lost = agg[b]
            ok = n - lost
            rows.append([round(start + (b + 0.5) * bw, 2),
                         round(s / ok, 2) if ok else None,
                         round(mn, 2) if ok else None,
                         round(mx, 2) if ok else None,
                         round(lost / n, 3), n])
        out[hid] = rows
    return {"now": now, "start": start, "bucket": bw, "data": out}


REPORT_COLS = [("Name", "name"), ("Address", "addr"), ("Resolved IP", "ip"),
               ("Group", "group"), ("Status", "health"), ("Last result", "last_status"),
               ("Status since", "since"), ("Now ms", "cur"), ("Avg ms", "avg"),
               ("Min ms", "min"), ("Max ms", "max"), ("Jitter ms", "jitter"),
               ("Loss % (window)", "loss"), ("Succeeded", "ok"), ("Failed", "fail"),
               ("Failed %", "fail_pct"), ("Failed in a row", "in_row"),
               ("Most failed in a row", "max_row"), ("Total pings", "total"),
               ("Last succeeded", "last_ok"), ("Last failed", "last_fail"),
               ("TTL", "ttl"), ("Reply from", "reply"), ("MAC address", "mac")]
TIME_KEYS = ("since", "last_ok", "last_fail")


def report_rows(focus=600):
    st = api_state(focus)
    rows = []
    for h in st["hosts"]:
        if h["parent"]:
            continue
        r = []
        for _, k in REPORT_COLS:
            v = h.get(k)
            if k in TIME_KEYS:
                v = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v)) if v else ""
            elif k == "health":
                v = (v or "").upper()
            r.append("" if v is None else v)
        rows.append(r)
    return [c for c, _ in REPORT_COLS], rows


def build_report(fmt, focus=600):
    """Return (bytes, content_type, extension) for csv / txt / html / xml."""
    hdr, rows = report_rows(focus)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    if fmt == "csv":
        buf = io.StringIO(); w = csv.writer(buf); w.writerow(hdr); w.writerows(rows)
        return buf.getvalue().encode("utf-8-sig"), "text/csv; charset=utf-8", "csv"
    if fmt in ("txt", "tab"):
        lines = ["\t".join(hdr)] + ["\t".join(str(c) for c in r) for r in rows]
        return ("\r\n".join(lines) + "\r\n").encode("utf-8-sig"), "text/plain; charset=utf-8", "txt"
    if fmt == "xml":
        root = ET.Element("netpulse_report", generated=stamp)
        for r in rows:
            item = ET.SubElement(root, "item")
            for (_, k), v in zip(REPORT_COLS, r):
                ET.SubElement(item, k).text = str(v)
        return (b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")
                ), "application/xml; charset=utf-8", "xml"
    import html as _h
    up = sum(1 for r in rows if r[4] in ("UP", "DEGRADED")); down = sum(1 for r in rows if r[4] == "DOWN")
    color = {"UP": "#1a9b5a", "DOWN": "#d63546", "DEGRADED": "#c98a00"}
    body = "".join("<tr>" + "".join(
        '<td%s>%s</td>' % (' style="color:%s;font-weight:700"' % color.get(c, "#333") if i == 4 else "",
                           _h.escape(str(c))) for i, c in enumerate(r)) + "</tr>" for r in rows)
    page = ("<!doctype html><html><head><meta charset='utf-8'><title>NetPulse report %s</title>"
            "<style>body{font:13px system-ui,sans-serif;margin:20px;color:#222}h1{font-size:20px;margin:0}"
            "p{color:#666}table{border-collapse:collapse}th,td{border:1px solid #ddd;padding:4px 8px;"
            "white-space:nowrap}th{background:#f2f5f8;text-align:left}tr:nth-child(even) td{background:#fafbfc}"
            "</style></head><body><h1>NetPulse report</h1><p>%s &middot; %d devices &middot; %d up &middot; "
            "%d down</p><table><tr>%s</tr>%s</table></body></html>") % (
        stamp, stamp, len(rows), up, down, "".join("<th>%s</th>" % c for c in hdr), body)
    return page.encode("utf-8"), "text/html; charset=utf-8", "html"


def report_dir():
    d = SETTINGS.get("autosave_dir") or os.path.join(APP_DIR, "reports")
    return os.path.abspath(os.path.expanduser(d))


def write_report(fmt, path=None):
    data, _, ext = build_report(fmt)
    if not path:
        d = report_dir(); os.makedirs(d, exist_ok=True)
        name = "netpulse-report" + (time.strftime("-%Y%m%d-%H%M%S") if SETTINGS.get("autosave_stamp") else "")
        path = os.path.join(d, name + "." + ext)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    return path


def autosave_tick():
    mins = float(SETTINGS.get("autosave_min") or 0)
    if mins <= 0:
        AUTOSAVE["next"] = 0
        return
    now = time.time()
    if not AUTOSAVE["next"]:
        AUTOSAVE["next"] = now + mins * 60
    elif now >= AUTOSAVE["next"]:
        AUTOSAVE["next"] = now + mins * 60
        try:
            AUTOSAVE["last_file"] = write_report(SETTINGS.get("autosave_fmt") or "html")
            AUTOSAVE["last"], AUTOSAVE["error"] = now, ""
        except Exception as e:
            AUTOSAVE["error"] = str(e)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="application/json", code=200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj).encode(), code=code)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 25 * 1024 * 1024:
            raise ValueError("File too large")
        return self.rfile.read(n) if n else b""

    # --- safety: only real browsers on this computer (or the LAN, with --lan) may use the API
    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip().lower()
        if host.startswith("["):
            host = host[1:host.find("]")] if "]" in host else host
        else:
            host = host.rsplit(":", 1)[0]
        return LAN_MODE[0] or host == "localhost" or _is_ip(host)   # blocks DNS rebinding

    def _is_local(self):
        host = (self.headers.get("Host") or "").lower()
        return self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1") and \
            (host.startswith("127.0.0.1") or host.startswith("localhost") or host.startswith("[::1]"))

    def do_GET(self):
        if not self._host_ok():
            return self._send(b"forbidden", "text/plain", 403)
        u = urlparse(self.path)
        q = parse_qs(u.query)
        focus = float(q.get("focus", ["600"])[0])
        if u.path in ("/", "/index.html"):
            self._send(PAGE.encode(), "text/html; charset=utf-8")
        elif u.path == "/np.js":            # lets the My Apps tile find NetPulse's port
            self._send(b"window.__netpulse=(window.__netpulse||[]).concat([%d]);"
                       % self.server.server_address[1], "application/javascript")
        elif u.path == "/api/state":
            self._json(api_state(focus, self._is_local()))
        elif u.path == "/api/history":
            ids = [i for i in q.get("ids", [""])[0].split(",") if i]
            self._json(api_history(ids, focus, int(q.get("buckets", ["400"])[0])))
        elif u.path in ("/api/export", "/api/export.csv"):
            fmt = q.get("fmt", ["csv"])[0]
            data, ctype, ext = build_report(fmt if fmt in ("csv", "txt", "html", "xml") else "csv", focus)
            self._send(data, ctype, extra={
                "Content-Disposition": "attachment; filename=netpulse-%s.%s"
                                       % (time.strftime("%Y%m%d-%H%M"), ext)})
        else:
            self._send(b"not found", "text/plain", 404)

    def do_POST(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if not self._host_ok() or self.headers.get("X-NetPulse") != "1":
            return self._json({"error": "Blocked: requests must come from the NetPulse page."}, 403)
        local = self._is_local()
        try:
            if u.path == "/api/import":
                raw = self._body()
                fn = unquote(self.headers.get("X-Filename", "paste.txt"))
                self._json(import_payload(raw, fn, q.get("group", [""])[0].strip(),
                                          q.get("mode", ["add"])[0]))
                return
            body = json.loads(self._body() or b"{}")
            if u.path == "/api/remove":
                with LOCK:
                    for hid in body.get("ids", []):
                        for k in [k for k, v in HOSTS.items() if v.parent == hid]:
                            del HOSTS[k]
                        HOSTS.pop(hid, None)
                save()
            elif u.path == "/api/clear":
                with LOCK:
                    HOSTS.clear()
                save()
            elif u.path == "/api/update":
                with LOCK:
                    h = HOSTS.get(body.get("id"))
                    if h:
                        h.name = str(body.get("name", h.name))[:80]
                        h.group = str(body.get("group", h.group))[:60]
                save()
            elif u.path == "/api/reset_counts":
                with LOCK:
                    for h in HOSTS.values():
                        h.ok_count = h.fail_count = h.max_fails = 0
                        h.last_ok = h.last_fail = None
                        del h.ts[:]; del h.ms[:]
            elif u.path == "/api/settings":
                for k, cast, lo, hi in (("interval", float, 0.5, 300), ("timeout", int, 200, 10000),
                                        ("down_after", int, 1, 20), ("warn_ms", float, 1, 10000),
                                        ("warn_loss", float, 0, 100), ("size", int, 0, 65500),
                                        ("autosave_min", float, 0, 1440)):
                    if k in body:
                        SETTINGS[k] = min(hi, max(lo, cast(body[k])))
                for k in ("paused", "df", "autosave_stamp"):
                    if k in body:
                        SETTINGS[k] = bool(body[k])
                if body.get("autosave_fmt") in ("csv", "txt", "html", "xml"):
                    SETTINGS["autosave_fmt"] = body["autosave_fmt"]
                if "autosave_min" in body:
                    AUTOSAVE["next"] = 0
                blocked = [k for k in LOCAL_ONLY if k in body and str(body[k]) != str(SETTINGS[k])
                           and not str(body[k]).startswith("(set on")]
                if blocked and not local:
                    save()
                    return self._json({"error": "Alert commands and the report folder can only be "
                                                "changed on the computer running NetPulse."}, 403)
                for k in LOCAL_ONLY:
                    if k in body and local:
                        SETTINGS[k] = str(body[k]).strip()[:500]
                save()
            elif u.path == "/api/save_report":
                if not local:
                    return self._json({"error": "Reports can only be saved from the host computer. "
                                                "Use Export to download one instead."}, 403)
                path = write_report(body.get("fmt") or SETTINGS.get("autosave_fmt") or "html")
                return self._json({"ok": True, "path": path})
            elif u.path == "/api/test_cmd":
                if not local:
                    return self._json({"error": "Only on the host computer."}, 403)
                which = "cmd_up" if body.get("which") == "up" else "cmd_down"
                if not SETTINGS.get(which):
                    return self._json({"error": "Type a command first, then Save."}, 400)
                fake = Host("192.0.2.1", "Test device", "Test")
                run_hook(SETTINGS[which], fake, "up" if which == "cmd_up" else "down", 0)
            elif u.path == "/api/trace":
                threading.Thread(target=run_trace, args=(body.get("id"),), daemon=True).start()
            elif u.path == "/api/clear_trace":
                clear_trace(body.get("id"))
            else:
                self._send(b"not found", "text/plain", 404)
                return
            self._json({"ok": True})
        except Exception as e:
            self._json({"error": str(e)}, 400)


def load_file(path, mode="replace"):
    with open(path, "rb") as f:
        raw = f.read()
    return import_payload(raw, os.path.basename(path), "", mode)


def headless_report(a):
    """--report: ping everything a few rounds, write the report, exit (no window)."""
    rounds = max(1, a.rounds)
    print("NetPulse: pinging %d devices, %d rounds..." % (
        sum(1 for h in HOSTS.values() if not h.parent), rounds))
    refresh_arp()
    for i in range(rounds):
        t0 = time.time()
        todo = [h for h in HOSTS.values() if h.addr != "*"]
        list(POOL.map(probe, todo))
        if i < rounds - 1:
            time.sleep(max(0, float(SETTINGS["interval"]) - (time.time() - t0)))
    refresh_arp()
    out = os.path.abspath(a.report)
    ext = os.path.splitext(out)[1].lower().lstrip(".")
    fmt = a.format or {"htm": "html", "html": "html", "xml": "xml", "txt": "txt",
                       "tsv": "txt", "csv": "csv"}.get(ext, "csv")
    write_report(fmt, out)
    st = api_state(600)
    hosts = [h for h in st["hosts"] if not h["parent"]]
    up = sum(1 for h in hosts if h["status"] == "up")
    print("Saved %s  (%d up, %d down)" % (out, up, len(hosts) - up))
    return 0 if up == len(hosts) else 2


def main():
    ap = argparse.ArgumentParser(
        description="NetPulse network monitor",
        epilog="Examples:\n"
               "  netpulse.py --load hosts.xlsx\n"
               "  netpulse.py --load hosts.csv --report status.html --rounds 3\n"
               "  netpulse.py --interval 5 --timeout 800 --lan",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8790, help="web page port (default 8790)")
    ap.add_argument("--lan", action="store_true", help="allow other computers to open the dashboard")
    ap.add_argument("--no-browser", action="store_true", help="don't open the browser")
    ap.add_argument("--load", metavar="FILE", help="load this .xlsx/.csv/.txt list (replaces the saved list)")
    ap.add_argument("--add", metavar="FILE", help="add this .xlsx/.csv/.txt list to the saved list")
    ap.add_argument("--report", metavar="FILE",
                    help="ping, save a report (.csv .txt .html .xml) and exit - no window")
    ap.add_argument("--rounds", type=int, default=3, help="pings per device for --report (default 3)")
    ap.add_argument("--format", choices=["csv", "txt", "html", "xml"], help="report format")
    ap.add_argument("--interval", type=float, help="seconds between pings")
    ap.add_argument("--timeout", type=int, help="ping timeout in ms")
    ap.add_argument("--size", type=int, help="ping packet size in bytes")
    a = ap.parse_args()
    if not PING_OK:
        print("  WARNING: the 'ping' command was not found, so every device will show DOWN.")
        print("  On Linux install it with:  sudo apt install iputils-ping\n")
    load()
    LAN_MODE.append(bool(a.report))
    for k in ("interval", "timeout", "size"):
        if getattr(a, k) is not None:
            SETTINGS[k] = getattr(a, k)
    try:
        if a.load:
            print("Loaded %(added)d devices" % load_file(a.load, "replace"))
        if a.add:
            print("Added %(added)d devices" % load_file(a.add, "add"))
    except Exception as e:
        sys.exit("Could not read the list: %s" % e)
    if a.report:
        sys.exit(headless_report(a))
    threading.Thread(target=monitor_loop, daemon=True).start()
    LAN_MODE[0] = bool(a.lan)
    bind = "0.0.0.0" if a.lan else "127.0.0.1"
    srv = None
    for port in range(a.port, a.port + 20):
        try:
            srv = ThreadingHTTPServer((bind, port), Handler)
            break
        except OSError:
            continue
    if not srv:
        sys.exit("No free port found near %d" % a.port)
    srv.daemon_threads = True
    url = "http://127.0.0.1:%d" % port
    print("\n  NetPulse is running ->  %s" % url)
    if a.lan:
        try:
            lan_ip = socket.gethostbyname(socket.gethostname())
            print("  On your network     ->  http://%s:%d" % (lan_ip, port))
        except Exception:
            pass
    print("  Keep this window open. Press Ctrl+C to stop.\n")
    if not a.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("Stopping...")
        save()


# ----------------------------------------------------------------- web page
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetPulse</title>
<link rel="icon" href="data:image/png;base64,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">
<style>
:root{--bg:#0a0e13;--panel:#111821;--panel2:#0e141c;--line:#1e2935;--line2:#2a3746;--text:#dce6f0;
--dim:#7f8e9e;--faint:#4f5d6c;--up:#2fd47e;--down:#ff4d5e;--warn:#f6b73c;--hi:#ff8b3d;--acc:#46c3ff;
--mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);
font:14px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
button,input,select,textarea{font:inherit;color:inherit}
button{background:var(--panel);border:1px solid var(--line2);border-radius:7px;padding:6px 12px;cursor:pointer}
button:hover{border-color:var(--acc)}
button.pri{background:var(--acc);color:#04121c;border-color:var(--acc);font-weight:600}
button:disabled{opacity:.5;cursor:default}
input,select,textarea{background:var(--panel2);border:1px solid var(--line2);border-radius:7px;padding:6px 10px;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--acc)}
.mono{font-family:var(--mono);font-size:12.5px}
.dim{color:var(--dim)} .r{text-align:right} .bad{color:var(--down)}
header{display:flex;align-items:center;gap:12px;padding:10px 18px;border-bottom:1px solid var(--line);
background:linear-gradient(#0f151d,#0b1016);position:sticky;top:0;z-index:5;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:9px;font-weight:700;letter-spacing:.5px;font-size:16px}
.pulse{width:11px;height:11px;border-radius:50%;background:var(--up);box-shadow:0 0 0 0 rgba(47,212,126,.6);animation:pl 2s infinite}
.pulse.off{background:var(--down);animation:none}
@keyframes pl{70%{box-shadow:0 0 0 9px rgba(47,212,126,0)}100%{box-shadow:0 0 0 0 rgba(47,212,126,0)}}
.seg{display:inline-flex;background:var(--panel2);border:1px solid var(--line2);border-radius:9px;padding:3px}
.seg button{border:0;background:transparent;padding:5px 12px;border-radius:6px;color:var(--dim)}
.seg button.on{background:var(--line2);color:var(--text)}
.mode button.on{background:var(--acc);color:#04121c;font-weight:600}
.spacer{flex:1}
#quickAdd{width:200px}
.lbl{font-size:11px;letter-spacing:1.2px;text-transform:uppercase;color:var(--dim)}
main{padding:16px 18px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;cursor:pointer;position:relative;overflow:hidden}
.card:hover{border-color:var(--line2)} .card.sel{border-color:var(--acc)}
.card .num{font:700 40px/1.1 var(--mono);margin-top:4px}
.card.up .num{color:var(--up)} .card.down .num{color:var(--down)} .card.deg .num{color:var(--warn)}
.card.down.alert{background:linear-gradient(135deg,rgba(255,77,94,.16),var(--panel) 60%);border-color:rgba(255,77,94,.5)}
.card .sub{font-size:12px;color:var(--dim)}
.ratio{display:flex;height:6px;border-radius:4px;overflow:hidden;margin:12px 0 14px;background:var(--line)}
.ratio i{display:block;height:100%;transition:width .4s} .ratio .u{background:var(--up)} .ratio .w{background:var(--warn)} .ratio .d{background:var(--down)} .ratio .p{background:var(--faint)}
.mwrap{display:grid;grid-template-columns:1fr 300px;gap:14px;align-items:start}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.tools{display:flex;gap:8px;align-items:center;padding:10px 12px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.tools input[type=search]{width:220px}
table{width:100%;border-collapse:collapse}
th{font-size:11px;letter-spacing:.8px;text-transform:uppercase;color:var(--dim);font-weight:600;text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap;user-select:none}
th.s{cursor:pointer} th.s:hover{color:var(--text)} th .ar{color:var(--acc)}
td{padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
#htable tbody tr{cursor:pointer} #htable tbody tr:hover{background:rgba(70,195,255,.05)}
tr.h-down td{background:rgba(255,77,94,.07)}
td small{display:block;color:var(--faint);font-size:11px}
.nm{max-width:240px;overflow:hidden;text-overflow:ellipsis}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--faint)}
.dot.up{background:var(--up);box-shadow:0 0 6px rgba(47,212,126,.7)} .dot.down{background:var(--down);box-shadow:0 0 8px rgba(255,77,94,.9);animation:bl 1s infinite}
.dot.degraded{background:var(--warn)} .dot.noreply{background:transparent;border:1px dashed var(--faint)}
@keyframes bl{50%{opacity:.35}}
.badge{font:600 11px var(--mono);padding:2px 7px;border-radius:5px;letter-spacing:.5px}
.badge.up{color:var(--up);background:rgba(47,212,126,.1)} .badge.down{color:var(--down);background:rgba(255,77,94,.12)}
.badge.degraded{color:var(--warn);background:rgba(246,183,60,.1)} .badge.pending{color:var(--dim);background:var(--line)}
canvas.spark{width:120px;height:22px;display:block}
button.x{border:0;background:none;color:var(--faint);padding:2px 6px} button.x:hover{color:var(--down)}
.log h3{margin:0;padding:12px 14px;border-bottom:1px solid var(--line);font-size:13px;display:flex;justify-content:space-between}
.log ul{list-style:none;margin:0;padding:0;max-height:calc(100vh - 290px);overflow:auto}
.log li{padding:8px 14px;border-bottom:1px solid var(--line);font-size:13px;cursor:pointer}
.log li:hover{background:rgba(70,195,255,.05)}
.log li .t{font:11px var(--mono);color:var(--faint)}
.log li.down b{color:var(--down)} .log li.up b{color:var(--up)}
.empty{padding:60px 20px;text-align:center;color:var(--dim)}
.empty h2{color:var(--text);margin:0 0 6px;font-size:20px}
.empty .big{font-size:42px;margin-bottom:8px}
/* plotter */
#vPlot{display:grid;grid-template-columns:250px 1fr;gap:14px;align-items:start}
#tlist{max-height:calc(100vh - 100px);overflow:auto}
#tlist .ti{display:flex;align-items:center;gap:9px;padding:8px 12px;border-bottom:1px solid var(--line);cursor:pointer}
#tlist .ti:hover{background:rgba(70,195,255,.05)} #tlist .ti.sel{background:rgba(70,195,255,.12);box-shadow:inset 3px 0 var(--acc)}
#tlist .ti .n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#tlist .ti .v{font:12px var(--mono);color:var(--dim)}
#tlist .gh{padding:6px 12px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--faint);background:var(--panel2);border-bottom:1px solid var(--line)}
.ptool{display:flex;align-items:center;gap:12px;padding:12px 14px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.ptool h2{margin:0;font-size:17px} .ptool .sub{font-size:12px;color:var(--dim)}
.hops td{padding:6px 10px} .hops tbody tr{cursor:pointer} .hops tbody tr:hover{background:rgba(70,195,255,.05)}
.hops tr.sel td{background:rgba(70,195,255,.1)} .hops tr.nr td{color:var(--faint)} .hops tr.tgt td{font-weight:600}
.gcell{width:38%;min-width:180px}
.lbar{position:relative;height:16px;background:repeating-linear-gradient(90deg,transparent 0 calc(25% - 1px),var(--line) calc(25% - 1px) 25%);border-radius:3px}
.lbar .rng{position:absolute;top:5px;height:6px;background:rgba(70,195,255,.25);border-radius:3px}
.lbar .avg{position:absolute;top:1px;width:3px;height:14px;margin-left:-1px;border-radius:2px;background:var(--up)}
.lbar .pl{position:absolute;left:0;bottom:-2px;height:3px;background:var(--down);border-radius:2px}
.tlhead{display:flex;align-items:center;gap:12px;padding:10px 14px;border-top:1px solid var(--line);font-size:13px;flex-wrap:wrap}
.legend{display:flex;gap:12px;font-size:11.5px;color:var(--dim);margin-left:auto}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.tlbox{padding:0 10px 10px} #tl{width:100%;height:280px;display:block}
.srow{display:grid;grid-template-columns:230px 1fr;border-bottom:1px solid var(--line);cursor:pointer}
.srow:hover{background:rgba(70,195,255,.04)}
.sinfo{padding:8px 12px;border-right:1px solid var(--line);min-width:0}
.sinfo b{display:inline-block;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle;margin-left:6px}
.sinfo .st{font:11.5px var(--mono);color:var(--dim);margin-top:3px}
.scv{width:100%;height:58px;display:block}
.saxis{display:grid;grid-template-columns:230px 1fr;font:11px var(--mono);color:var(--faint)}
.saxis div:last-child{display:flex;justify-content:space-between;padding:4px 8px}
/* modals */
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;z-index:20;padding:16px}
.modal.on{display:flex}
.box{background:var(--panel);border:1px solid var(--line2);border-radius:14px;width:560px;max-width:100%;max-height:92vh;overflow:auto;padding:20px}
.box h2{margin:0 0 4px;font-size:18px} .box p{color:var(--dim);margin:0 0 14px;font-size:13px}
.drop{border:2px dashed var(--line2);border-radius:12px;padding:26px;text-align:center;cursor:pointer;color:var(--dim)}
.drop:hover,.drop.over{border-color:var(--acc);color:var(--text)} .drop b{color:var(--text)}
.box textarea{width:100%;height:110px;margin-top:6px;font-family:var(--mono);font-size:12.5px}
.row{display:flex;gap:10px;align-items:center;margin-top:12px;flex-wrap:wrap}
.row label{display:flex;gap:6px;align-items:center}
.foot{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
.msg{margin-top:10px;font-size:13px} .msg.err{color:var(--down)} .msg.ok{color:var(--up)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.grid2 label{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--dim)}
.menu{position:relative;display:inline-block}
.menu .pop{display:none;position:absolute;right:0;top:calc(100% + 6px);background:var(--panel);border:1px solid var(--line2);border-radius:10px;padding:6px;z-index:15;min-width:210px;box-shadow:0 10px 30px rgba(0,0,0,.5)}
.menu.open .pop{display:block}
.pop button{display:block;width:100%;text-align:left;border:0;background:none;padding:7px 10px;border-radius:6px}
.pop button:hover{background:var(--line)} .pop hr{border:0;border-top:1px solid var(--line);margin:5px 0}
.pop label{display:flex;gap:8px;align-items:center;padding:4px 8px;font-size:13px;white-space:nowrap;cursor:pointer}
.pop .cols{max-height:60vh;overflow:auto}
button.on2{border-color:var(--acc);color:var(--acc)}
tr.ghead td{background:var(--panel2);font-weight:600;cursor:pointer;user-select:none;border-bottom:1px solid var(--line2)}
tr.ghead td .gc{font-weight:400;font-size:12px;margin-left:10px}
.ok{color:var(--up)}
.sec{grid-column:1/-1;margin-top:8px;padding-top:12px;border-top:1px solid var(--line);font-size:11px;letter-spacing:1.2px;text-transform:uppercase;color:var(--acc)}
.full{grid-column:1/-1} .grid2 .chk{flex-direction:row;align-items:center;gap:8px;color:var(--text);font-size:13px}
.hint{font-size:11.5px;color:var(--faint);margin-top:2px}
.inrow{display:flex;gap:6px} .inrow input{flex:1;min-width:0}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--acc);border-radius:10px;padding:10px 16px;z-index:40;display:none;max-width:90vw}
#tip{position:fixed;pointer-events:none;background:#06090d;border:1px solid var(--line2);border-radius:8px;padding:7px 10px;font:12px var(--mono);z-index:30;display:none;white-space:nowrap}
#offline{display:none;background:var(--down);color:#fff;text-align:center;padding:6px;font-size:13px}
@media(max-width:1000px){.mwrap,#vPlot{grid-template-columns:1fr}.cards{grid-template-columns:repeat(2,1fr)}.srow,.saxis{grid-template-columns:150px 1fr}}
</style></head><body>
<div id="noping" style="display:none;background:#7a4b00;color:#fff;text-align:center;padding:6px;font-size:13px">The <b>ping</b> command wasn't found on this computer, so everything shows DOWN. On Linux: <code>sudo apt install iputils-ping</code></div>
<div id="offline">Lost connection to NetPulse - is the netpulse.py window still open?</div>
<header>
  <div class="brand"><span class="pulse" id="pulse"></span>NetPulse</div>
  <div class="seg mode" id="modeSeg"><button data-m="monitor" class="on">&#9638; Monitor</button><button data-m="plot">&#8764; Plotter</button></div>
  <div class="spacer"></div>
  <span class="lbl">Window</span><div class="seg" id="focusSeg"></div>
  <input id="quickAdd" placeholder="Add IP / host, press Enter">
  <button id="btnImport" class="pri">Import Excel</button>
  <button id="btnPause" title="Pause / resume pinging">&#10073;&#10073;</button>
  <button id="btnSettings" title="Settings">&#9881;</button>
</header>
<main>
<section id="vMonitor">
  <div class="cards">
    <div class="card up" data-f="up"><div class="lbl">Up</div><div class="num" id="cUp">0</div><div class="sub" id="sUp">&nbsp;</div></div>
    <div class="card down" data-f="down"><div class="lbl">Down</div><div class="num" id="cDown">0</div><div class="sub" id="sDown">&nbsp;</div></div>
    <div class="card deg" data-f="degraded"><div class="lbl">Degraded</div><div class="num" id="cDeg">0</div><div class="sub" id="sDeg">&nbsp;</div></div>
    <div class="card" data-f="all"><div class="lbl">Total monitored</div><div class="num" id="cTot">0</div><div class="sub" id="sTot">&nbsp;</div></div>
  </div>
  <div class="ratio"><i class="u"></i><i class="w"></i><i class="d"></i><i class="p"></i></div>
  <div class="mwrap">
    <div class="panel">
      <div class="tools">
        <input type="search" id="q" placeholder="Search name, IP, group...">
        <select id="grp"></select>
        <div class="spacer"></div>
        <span class="dim" id="showing"></span>
        <button id="btnGroups" title="Show devices in collapsible groups">&#9776; Groups</button>
        <div class="menu" id="mCols"><button id="btnCols">Columns &#9662;</button><div class="pop"><div class="cols" id="colList"></div></div></div>
        <div class="menu" id="mExport"><button id="btnExport">Export &#9662;</button><div class="pop">
          <button data-x="csv">Download CSV (Excel)</button><button data-x="html">Download HTML report</button>
          <button data-x="xml">Download XML</button><button data-x="txt">Download text (tab separated)</button>
          <hr><button data-x="copy">Copy table to clipboard</button>
          <button data-x="save" class="localonly">Save report to reports folder now</button></div></div>
        <button id="btnClear">Clear list</button>
      </div>
      <div style="overflow:auto"><table id="htable"><thead></thead><tbody></tbody></table></div>
      <div class="empty" id="empty"><div class="big">&#128225;</div><h2>No devices yet</h2>
        <div>Import an Excel sheet of IPs, or type one in the box at the top.</div><br>
        <button class="pri" onclick="openImport()">Import Excel</button></div>
    </div>
    <div class="panel log"><h3><span>Up / down events</span><span class="dim" id="evCount"></span></h3><ul id="events"></ul></div>
  </div>
</section>
<section id="vPlot" hidden>
  <div class="panel" id="tlist"></div>
  <div class="panel" id="pmain"></div>
</section>
</main>

<div class="modal" id="mImport"><div class="box">
  <h2>Import IP list</h2>
  <p>Excel (.xlsx), CSV or text. Columns are found automatically: <b>IP / Host</b>, <b>Name</b>, <b>Group</b>.
  Each sheet in a workbook becomes its own group. Ranges like <span class="mono">10.0.0.1-50</span> and
  <span class="mono">10.0.0.0/24</span> are expanded. Add <span class="mono">:port</span> (like
  <span class="mono">192.168.1.10:80</span>) or a <b>Port</b> column to check a service with a TCP ping.</p>
  <div class="drop" id="drop"><b>Drop your file here</b> or click to choose<div id="fname" class="mono" style="margin-top:6px"></div></div>
  <input type="file" id="file" accept=".xlsx,.xlsm,.csv,.txt,.tsv" hidden>
  <div style="margin-top:14px" class="lbl">...or paste IPs (one per line, name after it is optional)</div>
  <textarea id="paste" placeholder="192.168.1.1  Router&#10;192.168.1.20 Printer&#10;8.8.8.8 Google DNS&#10;192.168.1.50:443 Camera web page&#10;10.0.0.1-20"></textarea>
  <div class="row"><span class="dim">Group (optional)</span><input id="impGroup" placeholder="e.g. Office" style="flex:1"></div>
  <div class="row"><label><input type="radio" name="mode" value="add" checked> Add to current list</label>
    <label><input type="radio" name="mode" value="replace"> Replace current list</label></div>
  <div class="msg" id="impMsg"></div>
  <div class="foot"><button onclick="closeModal('mImport')">Close</button><button class="pri" id="btnDoImport">Import</button></div>
</div></div>

<div class="modal" id="mSettings"><div class="box" style="width:640px">
  <h2>Settings</h2><p>Saved next to netpulse.py and used every time it starts.</p>
  <div class="grid2">
    <div class="sec">Pinging</div>
    <label>Ping every<select id="sInterval"><option value="1">1 second</option><option value="2">2 seconds</option><option value="5">5 seconds</option><option value="10">10 seconds</option><option value="30">30 seconds</option><option value="60">60 seconds</option></select></label>
    <label>Timeout (ms)<input id="sTimeout" type="number" min="200" max="10000" step="100"></label>
    <label>Packet size (bytes)<input id="sSize" type="number" min="0" max="65500"><span class="hint">32 is normal. Bigger sizes find MTU problems.</span></label>
    <label class="chk"><input type="checkbox" id="sDF"> Don't fragment</label>
    <div class="sec">Up / down rules</div>
    <label>Mark DOWN after N missed pings in a row<input id="sDownAfter" type="number" min="1" max="20"></label>
    <label>Degraded when avg latency over (ms)<input id="sWarn" type="number" min="1"></label>
    <label>Degraded when packet loss over (%)<input id="sLoss" type="number" min="0" max="100"></label>
    <div></div>
    <div class="sec">Sounds (this browser)</div>
    <label class="chk"><input type="checkbox" id="sSound"> Beep when something goes DOWN</label>
    <label class="chk"><input type="checkbox" id="sSoundUp"> Chime when something comes back UP</label>
    <div class="sec">Run a command <span class="localnote dim" style="text-transform:none;letter-spacing:0"></span></div>
    <label class="full">When a device goes DOWN<div class="inrow"><input id="sCmdDown" class="localfld mono" placeholder='e.g. powershell -c "Add-Content alerts.log \"{time} {name} {status}\""'><button type="button" data-test="down" class="localfld">Test</button></div></label>
    <label class="full">When a device comes back UP<div class="inrow"><input id="sCmdUp" class="localfld mono" placeholder="e.g. a script that texts or emails you"><button type="button" data-test="up" class="localfld">Test</button></div>
      <span class="hint">Fill-ins: {name} {addr} {ip} {group} {status} {time} {duration}. Also set as NETPULSE_NAME etc. Runs in the NetPulse folder.</span></label>
    <div class="sec">Auto-save reports</div>
    <label>Save a report every<select id="sAuto"><option value="0">Off</option><option value="1">1 minute</option><option value="5">5 minutes</option><option value="15">15 minutes</option><option value="30">30 minutes</option><option value="60">1 hour</option><option value="360">6 hours</option><option value="1440">24 hours</option></select></label>
    <label>Format<select id="sAutoFmt"><option value="html">HTML (opens in a browser)</option><option value="csv">CSV (opens in Excel)</option><option value="xml">XML</option><option value="txt">Text (tab separated)</option></select></label>
    <label class="full">Folder<input id="sAutoDir" class="localfld mono" placeholder="reports folder next to netpulse.py"><span class="hint" id="autoInfo"></span></label>
    <label class="chk full"><input type="checkbox" id="sStamp"> Put the date and time in each file name (keeps every report; off = overwrite one file)</label>
    <div class="sec">Counters</div>
    <div class="full"><button type="button" id="btnResetCounts">Reset all counts and graphs</button></div>
  </div>
  <div class="msg" id="setMsg"></div>
  <div class="foot"><button onclick="closeModal('mSettings')">Cancel</button><button class="pri" id="btnSaveSet">Save</button></div>
</div></div>
<div id="tip"></div><div id="toast"></div>

<script>
const FOCUS=[[60,'1m'],[300,'5m'],[600,'10m'],[1800,'30m'],[3600,'1h'],[21600,'6h'],[0,'All']];
const S={mode:'monitor',hosts:[],events:[],settings:{},focus:600,filter:'all',q:'',group:'',
  sort:{k:'status',d:1},sel:null,tlId:null,built:'',prev:{},sound:true,soundUp:true,file:null,cache:{},
  local:true,groupView:false,collapsed:{},cols:null};
try{S.sound=localStorage.getItem('np_sound')!=='0';S.soundUp=localStorage.getItem('np_sound_up')!=='0';S.focus=+(localStorage.getItem('np_focus')??600);
  S.groupView=localStorage.getItem('np_groups')==='1';S.collapsed=JSON.parse(localStorage.getItem('np_collapsed')||'{}');
  S.cols=JSON.parse(localStorage.getItem('np_cols')||'null')}catch(e){}
function store(k,v){try{localStorage.setItem(k,typeof v==='string'?v:JSON.stringify(v))}catch(e){}}
function toast(t,ms){const el=$('#toast');el.textContent=t;el.style.display='block';clearTimeout(el._t);el._t=setTimeout(()=>el.style.display='none',ms||3500)}
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtMs=v=>v==null?'—':(v<1?'<1':v<10?v.toFixed(1):Math.round(v))+' ms';
const num=v=>v==null?'—':(v<10?v.toFixed(1):Math.round(v));
function fmtDur(s){s=Math.max(0,Math.round(s));if(s<60)return s+'s';const m=Math.floor(s/60);if(m<60)return m+'m '+(s%60)+'s';
  const h=Math.floor(m/60);if(h<24)return h+'h '+(m%60)+'m';return Math.floor(h/24)+'d '+(h%24)+'h'}
const clock=t=>new Date(t*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
const byId=id=>S.hosts.find(h=>h.id===id);
const label=h=>h.name||h.addr;
async function api(p,o){o=o||{};if(o.method==='POST')o.headers=Object.assign({'X-NetPulse':'1'},o.headers||{});const r=await fetch(p,o);const j=await r.json().catch(()=>({}));if(!r.ok||j.error)throw new Error(j.error||r.statusText);return j}
const post=(p,b)=>api(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
function nice(v){if(!(v>0))return 10;const p=Math.pow(10,Math.floor(Math.log10(v)));for(const m of [1,1.5,2,2.5,3,4,5,6,8,10])if(v<=m*p)return m*p;return 10*p}
function latColor(v){const w=S.settings.warn_ms||150;return v<w?'#2fd47e':v<w*2?'#f6b73c':'#ff8b3d'}

/* ------------- header controls ------------- */
$('#focusSeg').innerHTML=FOCUS.map(([v,l])=>`<button data-f="${v}">${l}</button>`).join('');
function markFocus(){$$('#focusSeg button').forEach(b=>b.classList.toggle('on',+b.dataset.f===S.focus))}markFocus();
$('#focusSeg').onclick=e=>{const b=e.target.closest('button');if(!b)return;S.focus=+b.dataset.f;try{localStorage.setItem('np_focus',S.focus)}catch(e){}markFocus();tick(true)};
$('#modeSeg').onclick=e=>{const b=e.target.closest('button');if(b)setMode(b.dataset.m)};
function setMode(m){S.mode=m;$$('#modeSeg button').forEach(b=>b.classList.toggle('on',b.dataset.m===m));
  $('#vMonitor').hidden=m!=='monitor';$('#vPlot').hidden=m!=='plot';S.built='';render();if(m==='plot')drawPlot()}
$('#quickAdd').onkeydown=async e=>{if(e.key!=='Enter')return;const v=e.target.value.trim();if(!v)return;
  try{const r=await api('/api/import?mode=add',{method:'POST',headers:{'X-Filename':'quick.txt'},body:v});
    e.target.value='';if(!r.added)flash(e.target);tick(true)}catch(err){alert(err.message)}};
function flash(el){el.style.borderColor='var(--down)';setTimeout(()=>el.style.borderColor='',900)}
$('#btnImport').onclick=()=>openImport();
$('#btnPause').onclick=async()=>{await post('/api/settings',{paused:!S.settings.paused});tick(true)};
$('#btnSettings').onclick=()=>{const s=S.settings;$('#sInterval').value=String(+s.interval);$('#sTimeout').value=s.timeout;$('#sDownAfter').value=s.down_after;
  $('#sWarn').value=s.warn_ms;$('#sLoss').value=s.warn_loss;$('#sSize').value=s.size;$('#sDF').checked=!!s.df;
  $('#sSound').checked=S.sound;$('#sSoundUp').checked=S.soundUp;$('#sCmdDown').value=s.cmd_down||'';$('#sCmdUp').value=s.cmd_up||'';
  $('#sAuto').value=String(+s.autosave_min||0);if(!$('#sAuto').value)$('#sAuto').value='0';$('#sAutoFmt').value=s.autosave_fmt||'html';
  $('#sAutoDir').value=s.autosave_dir||'';$('#sStamp').checked=!!s.autosave_stamp;$('#setMsg').textContent='';
  $$('.localfld').forEach(el=>el.disabled=!S.local);
  $('.localnote').textContent=S.local?'':'(only on the computer running NetPulse)';
  const a=S.autosave||{};$('#autoInfo').textContent=(S.reportDir?'Saving to '+S.reportDir+'. ':'')+(a.error?'Last error: '+a.error:a.last?'Last saved '+clock(a.last)+' ('+a.file+')':'');
  $('#mSettings').classList.add('on')};
$('#btnSaveSet').onclick=async()=>{S.sound=$('#sSound').checked;S.soundUp=$('#sSoundUp').checked;store('np_sound',S.sound?'1':'0');store('np_sound_up',S.soundUp?'1':'0');
  const b={interval:+$('#sInterval').value,timeout:+$('#sTimeout').value,down_after:+$('#sDownAfter').value,warn_ms:+$('#sWarn').value,warn_loss:+$('#sLoss').value,
    size:+$('#sSize').value,df:$('#sDF').checked,autosave_min:+$('#sAuto').value,autosave_fmt:$('#sAutoFmt').value,autosave_stamp:$('#sStamp').checked};
  if(S.local){b.cmd_down=$('#sCmdDown').value;b.cmd_up=$('#sCmdUp').value;b.autosave_dir=$('#sAutoDir').value}
  try{await post('/api/settings',b);closeModal('mSettings');tick(true)}catch(e){$('#setMsg').className='msg err';$('#setMsg').textContent=e.message}};
$$('[data-test]').forEach(bt=>bt.onclick=async()=>{const m=$('#setMsg');try{
  await post('/api/settings',{cmd_down:$('#sCmdDown').value,cmd_up:$('#sCmdUp').value});
  await post('/api/test_cmd',{which:bt.dataset.test});m.className='msg ok';m.textContent='Ran the '+bt.dataset.test.toUpperCase()+' command for a pretend "Test device".'}
  catch(e){m.className='msg err';m.textContent=e.message}});
$('#btnResetCounts').onclick=async()=>{if(!confirm('Reset every count, graph and failure streak? Your device list stays.'))return;
  await post('/api/reset_counts');closeModal('mSettings');tick(true)};
function closeModal(id){$('#'+id).classList.remove('on')}
$$('.modal').forEach(m=>m.onclick=e=>{if(e.target===m)m.classList.remove('on')});
document.onkeydown=e=>{if(e.key==='Escape')$$('.modal').forEach(m=>m.classList.remove('on'))};

/* ------------- import ------------- */
function openImport(){S.file=null;$('#fname').textContent='';$('#impMsg').textContent='';$('#impMsg').className='msg';$('#mImport').classList.add('on')}
const drop=$('#drop');drop.onclick=()=>$('#file').click();
$('#file').onchange=e=>pick(e.target.files[0]);
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')};drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');pick(e.dataTransfer.files[0])};
document.addEventListener('dragover',e=>e.preventDefault());
document.addEventListener('drop',e=>{if(!e.target.closest('#drop')){e.preventDefault();const f=e.dataTransfer.files[0];if(f){openImport();pick(f)}}});
function pick(f){if(!f)return;S.file=f;$('#fname').textContent=f.name+'  ('+Math.ceil(f.size/1024)+' KB)'}
$('#btnDoImport').onclick=async()=>{const msg=$('#impMsg');msg.className='msg';
  const mode=document.querySelector('input[name=mode]:checked').value;const g=encodeURIComponent($('#impGroup').value.trim());
  let body,fn;if(S.file){body=await S.file.arrayBuffer();fn=S.file.name}else{body=$('#paste').value;fn='paste.txt';if(!body.trim()){msg.textContent='Choose a file or paste some IPs first.';msg.className='msg err';return}}
  if(mode==='replace'&&S.hosts.some(h=>!h.parent)&&!confirm('Replace your current list?'))return;
  msg.textContent='Importing...';
  try{const r=await api(`/api/import?mode=${mode}&group=${g}`,{method:'POST',headers:{'X-Filename':encodeURIComponent(fn)},body});
    msg.className='msg '+(r.added?'ok':'err');
    msg.textContent=r.added?`Added ${r.added} device${r.added>1?'s':''}`+(r.skipped?` (${r.skipped} already in the list)`:'')+'. Pinging now.'
      :r.found?`Nothing new - all ${r.skipped} were already in the list.`:'No IP addresses or hostnames were found in that file.';
    if(r.added){S.file=null;$('#fname').textContent='';$('#paste').value='';tick(true);setTimeout(()=>closeModal('mImport'),1200)}
  }catch(err){msg.className='msg err';msg.textContent=err.message}};

/* ------------- monitor view ------------- */
$('#q').oninput=e=>{S.q=e.target.value.toLowerCase();render()};
$('#grp').onchange=e=>{S.group=e.target.value;render()};
$$('.card').forEach(c=>c.onclick=()=>{S.filter=S.filter===c.dataset.f?'all':c.dataset.f;render()});
$('#htable thead').onclick=e=>{const th=e.target.closest('th.s');if(!th)return;const k=th.dataset.k;
  S.sort=S.sort.k===k?{k,d:-S.sort.d}:{k,d:1};render()};
$('#htable tbody').onclick=async e=>{const del=e.target.closest('[data-del]');
  if(del){e.stopPropagation();await post('/api/remove',{ids:[del.dataset.del]});tick(true);return}
  const gh=e.target.closest('tr.ghead');if(gh){const g=gh.dataset.g;S.collapsed[g]=!S.collapsed[g];store('np_collapsed',S.collapsed);render();return}
  const tr=e.target.closest('tr[data-id]');if(tr){S.sel=tr.dataset.id;S.tlId=null;setMode('plot')}};
$('#events').onclick=e=>{const li=e.target.closest('li[data-id]');if(li&&byId(li.dataset.id)){S.sel=li.dataset.id;S.tlId=null;setMode('plot')}};
$('#btnClear').onclick=async()=>{if(confirm('Remove every device from the list?')){await post('/api/clear');tick(true)}};
$('#btnGroups').onclick=()=>{S.groupView=!S.groupView;store('np_groups',S.groupView?'1':'0');render()};
$$('.menu > button').forEach(b=>b.onclick=e=>{e.stopPropagation();const m=b.parentNode,o=!m.classList.contains('open');$$('.menu').forEach(x=>x.classList.remove('open'));m.classList.toggle('open',o)});
document.addEventListener('click',e=>{if(!e.target.closest('.menu'))$$('.menu').forEach(x=>x.classList.remove('open'))});
$('#mExport .pop').onclick=async e=>{const b=e.target.closest('[data-x]');if(!b)return;const x=b.dataset.x;$('#mExport').classList.remove('open');
  if(x==='copy'){const t=await fetch('/api/export?fmt=txt&focus='+S.focus).then(r=>r.text());copyText(t.replace(/^﻿/,''))}
  else if(x==='save'){try{const r=await post('/api/save_report',{});toast('Saved '+r.path,6000)}catch(err){toast(err.message,6000)}}
  else location.href='/api/export?fmt='+x+'&focus='+S.focus};
async function copyText(t){try{await navigator.clipboard.writeText(t);toast('Copied the table. Paste it into Excel or an email.')}
  catch(e){const ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();
    let ok=false;try{ok=document.execCommand('copy')}catch(_){}ta.remove();toast(ok?'Copied the table. Paste it into Excel or an email.':'Your browser blocked copying. Use Download instead.')}}
const T=t=>t?new Date(t*1000).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'}):'—';
const COLS=[
 {k:'dot',l:'',fixed:1,cell:h=>`<span class="dot ${h.health}"></span>`},
 {k:'name',l:'Name',on:1,sort:h=>label(h).toLowerCase(),cls:'nm',cell:h=>esc(label(h))},
 {k:'addr',l:'Address',on:1,sort:h=>ipKey(h.addr),cls:'mono',cell:h=>esc(h.addr)+(h.port?' <span class="badge pending">TCP</span>':'')+(h.ip&&h.ip!==h.addr&&h.ip!==h.addr.split(':')[0]?`<small>${esc(h.ip)}</small>`:'')},
 {k:'group',l:'Group',on:1,sort:h=>h.group.toLowerCase(),cls:'dim',cell:h=>esc(h.group)},
 {k:'status',l:'Status',on:1,sort:h=>RANK[h.health],cell:h=>`<span class="badge ${h.health}">${h.health.toUpperCase()}</span>`},
 {k:'last_status',l:'Last result',sort:h=>h.last_status,cls:'dim',cell:h=>esc(h.last_status||'—')},
 {k:'cur',l:'Now',on:1,r:1,cls:'mono',cell:h=>fmtMs(h.cur)},
 {k:'avg',l:'Avg',on:1,r:1,cls:'mono',cell:h=>fmtMs(h.avg)},
 {k:'min',l:'Min',r:1,cls:'mono',cell:h=>fmtMs(h.min)},
 {k:'max',l:'Max',r:1,cls:'mono',cell:h=>fmtMs(h.max)},
 {k:'jitter',l:'Jitter',r:1,cls:'mono',cell:h=>fmtMs(h.jitter)},
 {k:'loss',l:'Loss',on:1,r:1,cls:'mono',tip:'Packet loss in the selected time window',cell:h=>`<span class="${h.loss>0?'bad':'dim'}">${h.sent?h.loss+'%':'—'}</span>`},
 {k:'ok',l:'Succeeded',r:1,cls:'mono',cell:h=>`<span class="ok">${h.ok}</span>`},
 {k:'fail',l:'Failed',r:1,cls:'mono',cell:h=>`<span class="${h.fail?'bad':'dim'}">${h.fail}</span>`},
 {k:'fail_pct',l:'Failed %',r:1,cls:'mono',tip:'Failed pings since NetPulse started (or since reset)',cell:h=>h.total?h.fail_pct+'%':'—'},
 {k:'in_row',l:'Fails in a row',on:1,r:1,cls:'mono',cell:h=>`<span class="${h.in_row?'bad':'dim'}">${h.in_row}</span>`},
 {k:'max_row',l:'Most in a row',r:1,cls:'mono',tip:'Longest run of failed pings',cell:h=>`<span class="${h.max_row?'bad':'dim'}">${h.max_row}</span>`},
 {k:'total',l:'Total pings',r:1,cls:'mono',cell:h=>h.total},
 {k:'last_ok',l:'Last succeeded',sort:h=>h.last_ok||0,cls:'dim',cell:h=>T(h.last_ok)},
 {k:'last_fail',l:'Last failed',sort:h=>h.last_fail||0,cls:'dim',cell:h=>T(h.last_fail)},
 {k:'ttl',l:'TTL',r:1,cls:'mono',cell:h=>h.ttl??'—'},
 {k:'reply',l:'Reply from',sort:h=>ipKey(h.reply||''),cls:'mono',cell:h=>esc(h.reply||'—')},
 {k:'mac',l:'MAC address',sort:h=>h.mac||'~',cls:'mono',tip:'Only for devices on your own network',cell:h=>esc(h.mac||'—')},
 {k:'spark',l:'Last 60 pings',on:1,nosort:1,cell:h=>`<canvas class="spark" data-id="${h.id}"></canvas>`},
 {k:'since',l:'For',on:1,sort:h=>h.since,cls:'dim',cell:h=>stateText(h)},
 {k:'del',l:'',fixed:1,cell:h=>`<button class="x" data-del="${h.id}" title="Remove">&#10005;</button>`}];
if(!S.cols)S.cols=COLS.filter(c=>c.on).map(c=>c.k);
function visCols(){return COLS.filter(c=>c.fixed||S.cols.includes(c.k))}
function buildColList(){$('#colList').innerHTML=COLS.filter(c=>!c.fixed).map(c=>`<label><input type="checkbox" data-c="${c.k}" ${S.cols.includes(c.k)?'checked':''}> ${c.l}</label>`).join('')+
  '<hr><button data-reset="1">Back to the default columns</button>'}
buildColList();
$('#colList').onclick=e=>{e.stopPropagation();if(e.target.dataset.reset){S.cols=COLS.filter(c=>c.on).map(c=>c.k);buildColList()}
  else{const c=e.target.dataset.c;if(!c)return;S.cols=e.target.checked?[...S.cols,c]:S.cols.filter(x=>x!==c)}store('np_cols',S.cols);S.headKey='';render()};
const RANK={down:0,degraded:1,pending:2,up:3,noreply:4};
function stateText(h){const d=fmtDur(Date.now()/1000-h.since);return h.status==='pending'?'waiting...':(h.status==='down'?'down ':'up ')+d}

function renderMonitor(mon){
  const groups=[...new Set(mon.map(h=>h.group).filter(Boolean))].sort();
  const gsel=$('#grp'),want=['',...groups].join('|');
  if(gsel.dataset.k!==want){gsel.dataset.k=want;gsel.innerHTML='<option value="">All groups</option>'+groups.map(g=>`<option>${esc(g)}</option>`).join('');gsel.value=S.group}
  gsel.style.display=groups.length?'':'none';
  let list=mon.filter(h=>(S.filter==='all'||h.health===S.filter)&&(!S.group||h.group===S.group)&&
    (!S.q||(h.name+' '+h.addr+' '+h.ip+' '+h.group+' '+(h.mac||'')).toLowerCase().includes(S.q)));
  const {k,d}=S.sort;const col=COLS.find(c=>c.k===k);
  const val=col&&col.sort?col.sort:(h=>h[k]??-1);
  list.sort((a,b)=>{const x=val(a),y=val(b);return (x<y?-1:x>y?1:ipKey(a.addr)<ipKey(b.addr)?-1:1)*d});
  const vc=visCols(),hk=vc.map(c=>c.k).join()+k+d;
  if(S.headKey!==hk){S.headKey=hk;$('#htable thead').innerHTML='<tr>'+vc.map(c=>`<th class="${c.fixed||c.nosort?'':'s'} ${c.r?'r':''}" data-k="${c.k}" ${c.tip?`title="${c.tip}"`:''}>${c.l}${c.k===k?`<span class="ar"> ${d>0?'▲':'▼'}</span>`:''}</th>`).join('')+'</tr>'}
  const row=h=>`<tr data-id="${h.id}" class="h-${h.health}">`+vc.map(c=>`<td class="${c.cls||''} ${c.r?'r':''}">${c.cell(h)}</td>`).join('')+'</tr>';
  const grouped=S.groupView&&groups.length;$('#btnGroups').classList.toggle('on2',!!grouped);$('#btnGroups').style.display=groups.length?'':'none';
  let html;
  if(grouped){const by={};list.forEach(h=>(by[h.group||'']??=[]).push(h));
    html=Object.keys(by).sort((a,b)=>(a===''?'~':a).localeCompare(b===''?'~':b)).map(g=>{const hs=by[g],c={up:0,down:0,degraded:0};hs.forEach(h=>c[h.health]=(c[h.health]||0)+1);const cl=S.collapsed[g];
      return `<tr class="ghead" data-g="${esc(g)}"><td colspan="${vc.length}">${cl?'&#9656;':'&#9662;'} ${esc(g||'Ungrouped')} <span class="dim gc">${hs.length} device${hs.length>1?'s':''}</span><span class="gc ok">${c.up+c.degraded} up</span>${c.down?`<span class="gc bad">${c.down} down</span>`:''}</td></tr>`+(cl?'':hs.map(row).join(''))}).join('')}
  else html=list.map(row).join('');
  $('#htable tbody').innerHTML=html;
  $$('canvas.spark').forEach(cv=>{const h=byId(cv.dataset.id);if(h)drawSpark(cv,h.spark)});
  $('#empty').style.display=mon.length?'none':'';
  $('#showing').textContent=mon.length?(list.length===mon.length?`${mon.length} devices`:`showing ${list.length} of ${mon.length}`):'';
  $('#events').innerHTML=S.events.length?S.events.map(e=>`<li class="${e.kind}" data-id="${e.id}"><div class="t">${new Date(e.t*1000).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'})}</div>
    ${esc(e.name)} <b>${e.kind==='down'?'went DOWN':'is back UP'}</b>${e.dur!=null?` <span class="dim">${e.kind==='down'?'after '+fmtDur(e.dur)+' up':'after '+fmtDur(e.dur)+' down'}</span>`:''}</li>`).join('')
    :'<li class="dim" style="cursor:default">Nothing yet. Changes from up to down (and back) show here.</li>';
  $('#evCount').textContent=S.events.length||'';
}
function ipKey(a){const m=a.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);return m?m.slice(1).map(x=>x.padStart(3,'0')).join('.'):'~'+a.toLowerCase()}
function sizeCanvas(cv){const dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;
  if(cv.width!==Math.round(W*dpr)||cv.height!==Math.round(H*dpr)){cv.width=Math.round(W*dpr);cv.height=Math.round(H*dpr)}
  const c=cv.getContext('2d');c.setTransform(dpr,0,0,dpr,0,0);c.clearRect(0,0,W,H);return [c,W,H]}
function drawSpark(cv,arr){const [c,W,H]=sizeCanvas(cv);const n=60,bw=W/n;
  const vals=arr.filter(v=>v>=0);const mx=Math.max(nice(Math.max(...vals,1)*1.1),5);
  c.fillStyle='#1a2430';c.fillRect(0,H-1,W,1);
  arr.forEach((v,i)=>{const x=(n-arr.length+i)*bw;
    if(v<0){c.fillStyle='#ff4d5e';c.fillRect(x,0,Math.max(1,bw-1),H)}
    else{const h=Math.max(2,v/mx*(H-2));c.fillStyle=latColor(v);c.fillRect(x,H-h,Math.max(1,bw-1),h)}})}

/* ------------- plotter view ------------- */
function renderPlot(mon){
  const groups={};mon.forEach(h=>(groups[h.group||'']??=[]).push(h));
  const keys=Object.keys(groups).sort();
  $('#tlist').innerHTML=`<div class="ti ${S.sel?'':'sel'}" data-id=""><span>&#9776;</span><span class="n"><b>All targets</b> <span class="dim">(${mon.length})</span></span></div>`+
    keys.map(g=>(keys.length>1||g?`<div class="gh">${esc(g||'Ungrouped')}</div>`:'')+groups[g].sort((a,b)=>RANK[a.health]-RANK[b.health]||ipKey(a.addr).localeCompare(ipKey(b.addr))).map(h=>
    `<div class="ti ${S.sel===h.id?'sel':''}" data-id="${h.id}"><span class="dot ${h.health}"></span><span class="n" title="${esc(h.addr)}">${esc(label(h))}</span><span class="v">${h.health==='down'?'<span class="bad">down</span>':num(h.cur)}</span></div>`).join('')).join('');
  if(S.sel&&!byId(S.sel))S.sel=null;
  if(!mon.length){$('#pmain').innerHTML=$('#empty').outerHTML.replace('id="empty"','');S.built='';return}
  S.sel?renderDetail(byId(S.sel)):renderSummary(mon);
}
$('#tlist').onclick=e=>{const t=e.target.closest('.ti');if(!t)return;S.sel=t.dataset.id||null;S.tlId=null;render();drawPlot()};

function renderSummary(mon){
  const list=[...mon].sort((a,b)=>RANK[a.health]-RANK[b.health]||ipKey(a.addr).localeCompare(ipKey(b.addr))).slice(0,60);
  const key='sum|'+list.map(h=>h.id).join(',');
  if(S.built!==key){S.built=key;
    $('#pmain').innerHTML=`<div class="ptool"><div><h2>All targets</h2><div class="sub">Latency over the selected window. Red = lost pings. Click a row to open its full graph and route trace.</div></div>
      <div class="legend"><span><i style="background:#2fd47e"></i>good</span><span><i style="background:#f6b73c"></i>slow</span><span><i style="background:#ff8b3d"></i>very slow</span><span><i style="background:#ff4d5e"></i>lost</span></div></div>
      <div id="srows">${list.map(h=>`<div class="srow" data-id="${h.id}"><div class="sinfo"><span class="dot ${h.health}"></span><b>${esc(label(h))}</b><div class="st" id="st${h.id}"></div></div><canvas class="scv" data-id="${h.id}"></canvas></div>`).join('')}</div>
      <div class="saxis"><div></div><div><span id="ax0"></span><span id="ax1"></span></div></div>
      ${mon.length>60?`<div class="dim" style="padding:10px 14px">Showing 60 of ${mon.length}. Problems are listed first.</div>`:''}`;
    $('#srows').onclick=e=>{const r=e.target.closest('.srow');if(r){S.sel=r.dataset.id;S.tlId=null;render();drawPlot()}};
    $$('.scv').forEach(attachTip);
  }
  list.forEach(h=>{const el=$('#st'+h.id);if(el)el.innerHTML=`${esc(h.addr)}<br>avg ${num(h.avg)} · max ${num(h.max)} · <span class="${h.loss?'bad':''}">${h.loss}% loss</span>`;
    const dot=el?.parentNode.querySelector('.dot');if(dot)dot.className='dot '+h.health});
}

function renderDetail(t){
  const hops=S.hosts.filter(h=>h.parent===t.id).sort((a,b)=>a.hop-b.hop);
  const rows=[...hops,t];
  if(!S.tlId||!rows.some(r=>r.id===S.tlId))S.tlId=t.id;
  const key='det|'+t.id+'|'+rows.map(r=>r.id).join(',');
  if(S.built!==key){S.built=key;
    $('#pmain').innerHTML=`<div class="ptool"><span class="dot" id="pdot"></span><div><h2>${esc(label(t))}</h2><div class="sub" id="psub"></div></div><div class="spacer"></div>
      <button id="btnClrTrace" style="display:none">Hide route</button><button id="btnTrace" class="pri"></button></div>
      <div style="overflow:auto"><table class="hops"><thead><tr><th class="r">Hop</th><th class="r">Count</th><th>IP</th><th>Name</th><th class="r">Avg</th><th class="r">Min</th><th class="r">Max</th><th class="r">Cur</th><th class="r">Jitter</th><th class="r">PL%</th>
      <th class="gcell"><div style="display:flex;justify-content:space-between"><span>0 ms</span><span id="gscale"></span></div></th></tr></thead><tbody id="hopBody"></tbody></table></div>
      <div class="tlhead"><span>Latency over time — <b id="tlName"></b></span><span class="dim" id="tlStats"></span>
      <div class="legend"><span><i style="background:#2fd47e"></i>good</span><span><i style="background:#f6b73c"></i>slow</span><span><i style="background:#ff8b3d"></i>very slow</span><span><i style="background:#ff4d5e"></i>packet loss</span></div></div>
      <div class="tlbox"><canvas id="tl"></canvas></div>`;
    $('#btnTrace').onclick=async()=>{await post('/api/trace',{id:t.id});tick(true)};
    $('#btnClrTrace').onclick=async()=>{await post('/api/clear_trace',{id:t.id});S.tlId=t.id;tick(true)};
    $('#hopBody').onclick=e=>{const tr=e.target.closest('tr[data-id]');if(tr&&byId(tr.dataset.id).addr!=='*'){S.tlId=tr.dataset.id;render();drawPlot()}};
    attachTip($('#tl'));
  }
  $('#pdot').className='dot '+t.health;
  $('#psub').innerHTML=`${esc(t.addr)}${t.ip&&t.ip!==t.addr?' · '+esc(t.ip):''}${t.group?' · '+esc(t.group):''} · <span class="badge ${t.health}">${t.health.toUpperCase()}</span> ${stateText(t)}${t.trace_msg?' · '+esc(t.trace_msg):''}`;
  const tb=$('#btnTrace');tb.disabled=t.trace==='running';tb.textContent=t.trace==='running'?'Tracing...':hops.length?'Re-trace route':'Trace route';
  $('#btnClrTrace').style.display=hops.length?'':'none';
  const scale=nice(Math.max(...rows.map(r=>r.max||0).filter(v=>v>0),...rows.map(r=>(r.avg||0)*1.5),5));
  $('#gscale').textContent=scale+' ms';
  const pct=v=>Math.min(100,v/scale*100);
  $('#hopBody').innerHTML=rows.map(r=>{const nr=r.addr==='*',tgt=r.id===t.id;
    return `<tr data-id="${r.id}" class="${r.id===S.tlId?'sel':''} ${nr?'nr':''} ${tgt?'tgt':''}">
      <td class="r mono">${r.hop??(tgt?(hops.length?hops.length+1:'—'):'')}</td><td class="r mono">${nr?'':r.sent}</td>
      <td class="mono">${nr?'*':esc(r.ip||r.addr)}</td><td class="nm">${esc(nr?'no reply':tgt?label(r):r.name)}</td>
      <td class="r mono">${nr?'':num(r.avg)}</td><td class="r mono">${nr?'':num(r.min)}</td><td class="r mono">${nr?'':num(r.max)}</td>
      <td class="r mono">${nr?'':r.cur==null&&r.sent?'<span class="bad">lost</span>':num(r.cur)}</td><td class="r mono">${nr?'':num(r.jitter)}</td>
      <td class="r mono ${r.loss>0?'bad':''}">${nr?'':r.loss}</td>
      <td class="gcell">${nr||r.avg==null?(nr?'':'<div class="lbar">'+(r.sent?'<i class="pl" style="width:100%"></i>':'')+'</div>'):
        `<div class="lbar"><i class="rng" style="left:${pct(r.min)}%;width:${Math.max(.5,pct(r.max)-pct(r.min))}%"></i><i class="avg" style="left:${pct(r.avg)}%;background:${latColor(r.avg)}"></i>${r.loss>0?`<i class="pl" style="width:${r.loss}%"></i>`:''}</div>`}</td></tr>`}).join('');
  const tl=byId(S.tlId);$('#tlName').textContent=tl.id===t.id?label(t):`hop ${tl.hop} · ${tl.addr}${tl.name?' ('+tl.name+')':''}`;
  $('#tlStats').innerHTML=`avg ${fmtMs(tl.avg)} · min ${fmtMs(tl.min)} · max ${fmtMs(tl.max)} · jitter ${fmtMs(tl.jitter)} · <span class="${tl.loss?'bad':''}">${tl.loss}% loss</span> of ${tl.sent}`;
}

async function drawPlot(){
  if(S.mode!=='plot')return;
  let ids,cvs;
  if(S.sel){const cv=$('#tl');if(!cv||!S.tlId)return;ids=[S.tlId];cvs=[[cv,S.tlId]]}
  else{cvs=$$('.scv').map(c=>[c,c.dataset.id]);ids=cvs.map(x=>x[1]);if(!ids.length)return}
  const W=cvs[0][0].clientWidth||600;const buckets=Math.max(60,Math.min(900,Math.floor(W/(S.sel?2:3))));
  let h;try{h=await api(`/api/history?ids=${ids.join(',')}&focus=${S.focus}&buckets=${buckets}`)}catch(e){return}
  S.cache={h,cvs};paintPlot();
}
function paintPlot(){const {h,cvs}=S.cache;if(!h)return;
  cvs.forEach(([cv,id])=>{if(document.body.contains(cv))drawTimeline(cv,h.data[id]||[],h,!S.sel)});
  if(!S.sel){$('#ax0')&&($('#ax0').textContent=clock(h.start));$('#ax1')&&($('#ax1').textContent=clock(h.now))}}
window.addEventListener('resize',()=>{clearTimeout(window._rz);window._rz=setTimeout(paintPlot,120)});

function drawTimeline(cv,data,h,compact){
  const [c,W,H]=sizeCanvas(cv);
  const pl=compact?6:46,pr=compact?40:10,pt=compact?5:10,pb=compact?5:24,pw=W-pl-pr,ph=H-pt-pb;
  const t0=h.start,t1=h.now,span=Math.max(1,t1-t0);
  const maxes=data.map(d=>d[3]).filter(v=>v!=null).sort((a,b)=>a-b);
  const p95=maxes.length?maxes[Math.floor(maxes.length*.97)]:10;const ymax=nice(Math.max(p95*1.15,compact?5:10));
  const X=t=>pl+(t-t0)/span*pw, Y=v=>pt+ph-Math.min(v,ymax)/ymax*ph;
  const bw=Math.max(1,Math.max(h.bucket,+S.settings.interval||2)/span*pw);
  // grid
  c.font='11px ui-monospace,Menlo,Consolas,monospace';c.textBaseline='middle';
  const lines=compact?2:5;
  for(let i=0;i<=lines;i++){const v=ymax*i/lines,y=Y(v);c.fillStyle=i?'#18222d':'#2a3746';c.fillRect(pl,Math.round(y),pw,1);
    if(!compact){c.fillStyle='#5f6e7e';c.textAlign='right';c.fillText(Math.round(v)+'',pl-6,y)}}
  if(compact){c.fillStyle='#5f6e7e';c.textAlign='left';c.fillText(ymax+'ms',pl+pw+5,pt+6)}
  else{c.textAlign='center';const nt=Math.max(2,Math.floor(pw/110));for(let i=0;i<=nt;i++){const t=t0+span*i/nt,x=X(t);
      c.fillStyle='#18222d';c.fillRect(Math.round(x),pt,1,ph);c.fillStyle='#5f6e7e';c.fillText(clock(t),Math.min(Math.max(x,pl+28),pl+pw-28),H-10)}
    c.save();c.translate(11,pt+ph/2);c.rotate(-Math.PI/2);c.textAlign='center';c.fillText('ms',0,0);c.restore()}
  // warn threshold
  const w=+S.settings.warn_ms||150;if(w<ymax){c.setLineDash([4,4]);c.strokeStyle='rgba(246,183,60,.35)';c.beginPath();c.moveTo(pl,Y(w)+.5);c.lineTo(pl+pw,Y(w)+.5);c.stroke();c.setLineDash([])}
  // bars
  for(const d of data){const x=X(d[0])-bw/2;
    if(d[4]>0){c.fillStyle=`rgba(255,77,94,${.3+.7*d[4]})`;c.fillRect(x,pt,bw,ph)}
    if(d[1]!=null){const y=Y(d[1]);c.fillStyle=latColor(d[1]);c.globalAlpha=.85;c.fillRect(x,y,bw,pt+ph-y);c.globalAlpha=1;
      if(!compact&&d[3]>d[1]){c.fillStyle='rgba(220,230,240,.35)';c.fillRect(x+bw/2-.5,Y(d[3]),1,Y(d[1])-Y(d[3]))}}}
  // avg line
  c.strokeStyle='rgba(235,242,250,.9)';c.lineWidth=compact?1:1.3;c.beginPath();let on=false,lastT=null;
  const gap=Math.max(h.bucket,+S.settings.interval||2)*3;
  for(const d of data){if(d[1]==null||(lastT!=null&&d[0]-lastT>gap)){on=false}if(d[1]!=null){const x=X(d[0]),y=Y(d[1]);on?c.lineTo(x,y):c.moveTo(x,y);on=true;lastT=d[0]}}
  c.stroke();
  if(!data.length){c.fillStyle='#5f6e7e';c.textAlign='center';c.fillText('waiting for data...',pl+pw/2,pt+ph/2)}
  cv._g={data,X,t0,span,pl,pw,bw};
}
function attachTip(cv){const tip=$('#tip');
  cv.onmousemove=e=>{const g=cv._g;if(!g||!g.data.length){tip.style.display='none';return}
    const r=cv.getBoundingClientRect(),x=e.clientX-r.left;const t=g.t0+(x-g.pl)/g.pw*g.span;
    let best=null,bd=1e18;for(const d of g.data){const dd=Math.abs(d[0]-t);if(dd<bd){bd=dd;best=d}}
    if(!best||Math.abs(g.X(best[0])-x)>Math.max(12,g.bw)){tip.style.display='none';return}
    const lost=Math.round(best[4]*best[5]);
    tip.innerHTML=`${clock(best[0])}<br>${best[1]==null?'<span class="bad">no reply</span>':`avg ${fmtMs(best[1])}<br>min ${fmtMs(best[2])} · max ${fmtMs(best[3])}`}${lost?`<br><span class="bad">${lost} of ${best[5]} lost</span>`:best[5]>1?`<br><span class="dim">${best[5]} pings</span>`:''}`;
    tip.style.display='block';tip.style.left=Math.min(e.clientX+14,innerWidth-170)+'px';tip.style.top=(e.clientY+14)+'px'};
  cv.onmouseleave=()=>tip.style.display='none'}

/* ------------- main loop ------------- */
function render(){
  const mon=S.hosts.filter(h=>!h.parent);
  const c={up:0,down:0,degraded:0,pending:0};mon.forEach(h=>c[h.health]=(c[h.health]||0)+1);
  const tot=mon.length||1;
  $('#cUp').textContent=c.up;$('#cDown').textContent=c.down;$('#cDeg').textContent=c.degraded;$('#cTot').textContent=mon.length;
  $('#sUp').textContent=mon.length?Math.round((c.up+c.degraded)/tot*100)+'% reachable':'';
  $('#sDown').textContent=c.down?'click to show them':'all clear';
  $('#sDeg').textContent=`slow or losing pings`;
  $('#sTot').textContent=c.pending?c.pending+' waiting for first reply':(S.settings.paused?'PAUSED':'every '+S.settings.interval+'s');
  $('.card.down').classList.toggle('alert',c.down>0);
  $$('.card').forEach(el=>el.classList.toggle('sel',S.filter===el.dataset.f&&S.filter!=='all'));
  const R=$('.ratio');R.querySelector('.u').style.width=c.up/tot*100+'%';R.querySelector('.w').style.width=c.degraded/tot*100+'%';
  R.querySelector('.d').style.width=c.down/tot*100+'%';R.querySelector('.p').style.width=c.pending/tot*100+'%';
  document.title=(c.down?`(${c.down} down) `:'')+'NetPulse';
  $('#btnPause').innerHTML=S.settings.paused?'&#9654; Resume':'&#10073;&#10073;';
  $('#pulse').classList.toggle('off',!!S.settings.paused);
  S.mode==='monitor'?renderMonitor(mon):renderPlot(mon);
}
function checkAlerts(){let newDown=0,newUp=0;
  S.hosts.forEach(h=>{if(h.parent)return;const p=S.prev[h.id];if(h.status==='down'&&p&&p!=='down')newDown++;if(h.status==='up'&&p==='down')newUp++;S.prev[h.id]=h.status});
  if(newDown&&S.sound)beep();else if(newUp&&S.soundUp)chime()}
function chime(){try{const a=new (window.AudioContext||window.webkitAudioContext)();[0,.12,.24].forEach((d,i)=>{const o=a.createOscillator(),g=a.createGain();
  o.frequency.value=[523,659,784][i];o.type='sine';g.gain.setValueAtTime(.08,a.currentTime+d);g.gain.exponentialRampToValueAtTime(.0001,a.currentTime+d+.35);
  o.connect(g).connect(a.destination);o.start(a.currentTime+d);o.stop(a.currentTime+d+.36)})}catch(e){}}
function beep(){try{const a=new (window.AudioContext||window.webkitAudioContext)();[0,.22].forEach(d=>{const o=a.createOscillator(),g=a.createGain();
  o.frequency.value=d?520:880;o.type='square';g.gain.setValueAtTime(.06,a.currentTime+d);g.gain.exponentialRampToValueAtTime(.0001,a.currentTime+d+.2);
  o.connect(g).connect(a.destination);o.start(a.currentTime+d);o.stop(a.currentTime+d+.2)})}catch(e){}}
let timer=null,busy=false;
async function tick(now){clearTimeout(timer);if(busy&&!now){timer=setTimeout(tick,1500);return}busy=true;
  try{const d=await api('/api/state?focus='+S.focus);S.hosts=d.hosts;S.events=d.events;S.settings=d.settings;S.local=d.local;S.autosave=d.autosave;S.reportDir=d.report_dir;
    $$('.localonly').forEach(el=>el.style.display=d.local?'':'none');
    $('#offline').style.display='none';$('#noping').style.display=d.ping_ok?'none':'block';checkAlerts();render();await drawPlot()}
  catch(e){$('#offline').style.display='block'}
  finally{busy=false;timer=setTimeout(tick,1500)}}
tick();
</script></body></html>"""

if __name__ == "__main__":
    main()
