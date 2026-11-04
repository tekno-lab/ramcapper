"""RamCapper - RAM monitor + limiter for Windows.

Samples memory per app every 2s, stores history in SQLite, serves a local dashboard
on http://127.0.0.1:8765 and enforces optional per-app limits.
"""
import atexit
import ctypes
import heapq
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from collections import deque
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import psutil

FROZEN = getattr(sys, "frozen", False)
HERE = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))   # bundled resources
APP_DIR = os.path.dirname(sys.executable) if FROZEN else os.path.dirname(os.path.abspath(__file__))


POINTERS = [os.path.join(APP_DIR, "datadir.txt"),
            os.path.join(os.environ.get("APPDATA", APP_DIR), "RamCapper", "datadir.txt")]


def _data_dir():
    """Where history.db and config.json live, highest priority first:
    --data DIR > RAMCAPPER_DATA > datadir.txt (next to the exe, else %APPDATA%\\RamCapper) > <app dir>."""
    src = "arg"
    arg = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--data=")), None)
    if arg is None and "--data" in sys.argv:
        i = sys.argv.index("--data")
        arg = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
    if not arg:
        src, arg = "env", os.environ.get("RAMCAPPER_DATA")
    if not arg:
        src = "setting"
        for p in POINTERS:
            try:
                with open(p, encoding="utf-8") as f:
                    arg = f.read().strip()
                if arg:
                    break
            except OSError:
                pass
    if not arg:
        src = "default"
    d = os.path.abspath(os.path.expandvars(os.path.expanduser(arg))) if arg else APP_DIR
    os.makedirs(d, exist_ok=True)
    return d, src


DATA_DIR, DATA_SOURCE = _data_dir()
DB_PATH = os.path.join(DATA_DIR, "history.db")
CFG_PATH = os.path.join(DATA_DIR, "config.json")
PORT =int(os.environ.get("RAMCAPPER_PORT", 8765))
TICK = 2.0
PERSIST_EVERY = 5.0
RETENTION = 3 * 86400
TOP_STORE = 12
MB = 1024 * 1024
CAP_MIN = 100 * MB
RANGES = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "3d": 259200}
ACTIONS = {"notify", "trim", "cap", "terminate"}
COOLDOWN = {"notify": 120, "trim": 30, "terminate": 10}

PROTECTED = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "fontdrvhost.exe", "memory compression", "system idle process", "secure system",
}

# ---------------------------------------------------------------- win32 helpers
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.SetProcessWorkingSetSizeEx.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t, wintypes.DWORD]
psapi.EmptyWorkingSet.argtypes = [wintypes.HANDLE]
PROCESS_QUERY = 0x0400
PROCESS_SET_QUOTA = 0x0100
HARDWS_MAX_ENABLE, HARDWS_MAX_DISABLE = 0x4, 0x8


class MEMSTATUS(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def mem_status():
    s = MEMSTATUS()
    s.dwLength = ctypes.sizeof(s)
    k32.GlobalMemoryStatusEx(ctypes.byref(s))
    return s


k32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMSTATUS)]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _with_handle(pid, fn):
    h = k32.OpenProcess(PROCESS_QUERY | PROCESS_SET_QUOTA, False, pid)
    if not h:
        return False
    try:
        return bool(fn(h))
    finally:
        k32.CloseHandle(h)


user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.GetClipboardOwner.restype = wintypes.HWND
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
CLIPBOARD_PROCS = {"rdpclip.exe", "textinputhost.exe", "clipup.exe"}


def clipboard_pids():
    """Processes that hold or serve the clipboard. Trimming them can drop delayed-render data / history,
    so every trim and cap skips them."""
    pids = set()
    try:
        hwnd = user32.GetClipboardOwner()
        if hwnd:
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                pids.add(pid.value)
    except Exception:
        pass
    try:  # the svchost hosting the Clipboard User Service (clipboard history / cloud sync)
        for s in psutil.win_service_iter():
            if s.name().lower().startswith(("cbdhsvc", "cdpusersvc")):
                p = s.as_dict().get("pid")
                if p:
                    pids.add(p)
    except Exception:
        pass
    for p in psutil.process_iter(["pid", "name"]):
        if (p.info["name"] or "").lower() in CLIPBOARD_PROCS:
            pids.add(p.info["pid"])
    return pids


def trim_pid(pid):
    return _with_handle(pid, psapi.EmptyWorkingSet)


def cap_pid(pid, max_bytes):
    return _with_handle(pid, lambda h: k32.SetProcessWorkingSetSizeEx(h, 204800, max_bytes, HARDWS_MAX_ENABLE))


def uncap_pid(pid):
    return _with_handle(pid, lambda h: k32.SetProcessWorkingSetSizeEx(h, ctypes.c_size_t(-1).value, ctypes.c_size_t(-1).value, HARDWS_MAX_DISABLE) or True)


# ---------------------------------------------------------------- storage
wlock = threading.Lock()
wdb = sqlite3.connect(DB_PATH, check_same_thread=False)
wdb.execute("PRAGMA journal_mode=WAL")
wdb.executescript("""
CREATE TABLE IF NOT EXISTS sys(ts INTEGER, used INTEGER, total INTEGER, commit_used INTEGER);
CREATE TABLE IF NOT EXISTS app(ts INTEGER, name TEXT, rss INTEGER, procs INTEGER);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, app TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS devices(mac TEXT PRIMARY KEY, ip TEXT, host TEXT, first_seen INTEGER, last_seen INTEGER);
CREATE INDEX IF NOT EXISTS sys_ts ON sys(ts);
CREATE INDEX IF NOT EXISTS app_ts ON app(ts);
""")
wdb.commit()


def rdb():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def log_event(kind, app, detail):
    with wlock:
        wdb.execute("INSERT INTO events(ts,kind,app,detail) VALUES(?,?,?,?)", (int(time.time()), kind, app, detail))
        wdb.commit()


# ---------------------------------------------------------------- config
MODULES = ("network", "storage")
DEFAULT_CFG = {"rules": [], "global": {"enabled": False, "threshold": 90, "cooldown": 60},
               "modules": {"network": False, "storage": False}}
cfg_lock = threading.Lock()


def load_cfg():
    try:
        with open(CFG_PATH, encoding="utf-8") as f:
            c = json.load(f)
        c.setdefault("rules", [])
        c.setdefault("global", dict(DEFAULT_CFG["global"]))
        c.setdefault("modules", dict(DEFAULT_CFG["modules"]))
        return c
    except Exception:
        return json.loads(json.dumps(DEFAULT_CFG))


CFG = load_cfg()


def module_on(name):
    return bool(CFG.get("modules", {}).get(name))


def save_cfg():
    with open(CFG_PATH, "w", encoding="utf-8") as f:
        json.dump(CFG, f, indent=2)


def clean_cfg(c):
    rules = []
    for r in c.get("rules", []):
        name = str(r.get("name", "")).strip().lower()
        if not name or r.get("action") not in ACTIONS:
            continue
        rules.append({
            "id": str(r.get("id") or uuid.uuid4().hex[:8]),
            "name": name,
            "limit_mb": max(50, min(int(r.get("limit_mb", 1024)), 4_000_000)),
            "action": r["action"],
            "enabled": bool(r.get("enabled", True)),
            "grace": max(1, min(int(r.get("grace", 3)), 60)),
        })
    g = c.get("global", {})
    return {"rules": rules, "global": {
        "enabled": bool(g.get("enabled", False)),
        "threshold": max(50, min(int(g.get("threshold", 90)), 99)),
        "cooldown": max(15, min(int(g.get("cooldown", 60)), 3600)),
    }}


# ---------------------------------------------------------------- live state
class State:
    lock = threading.Lock()
    sysinfo = {}
    apps = {}
    live = {}            # key -> deque[(ts, rss)]
    capped = {}          # pid -> (create_time, bytes)
    breach = {}
    last_fire = {}
    last_global = 0.0
    last_persist = 0.0
    last_prune = 0.0
    last_cap_warn = 0.0


ST = State()


def collect():
    apps = {}
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            mi = p.info["memory_info"]
            if mi is None:
                continue
            pid = p.info["pid"]
            name = (p.info["name"] or f"pid {pid}").lower()
            a = apps.get(name)
            if a is None:
                a = apps[name] = {"name": name, "rss": 0, "private": 0, "pids": []}
            a["rss"] += mi.rss
            a["private"] += getattr(mi, "private", mi.rss)
            a["pids"].append((pid, mi.rss))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return apps


def trim_apps(keys=None):
    """Empty the working set of processes (all, or only those named in keys). Returns (freed, ok, failed)."""
    freed = ok = failed = 0
    skip = clipboard_pids()
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            pid = p.info["pid"]
            if pid in (0, 4) or pid in skip or p.info["memory_info"] is None:
                continue
            if keys is not None and (p.info["name"] or "").lower() not in keys:
                continue
            before = p.info["memory_info"].rss
            if trim_pid(pid):
                ok += 1
                try:
                    freed += max(0, before - p.memory_info().rss)
                except psutil.Error:
                    pass
            else:
                failed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return freed, ok, failed


def kill_procs(pids):
    killed = 0
    me = os.getpid()
    for pid in pids:
        if pid == me or pid in (0, 4):
            continue
        try:
            p = psutil.Process(pid)
            if p.name().lower() in PROTECTED:
                continue
            p.kill()
            killed += 1
        except psutil.Error:
            pass
    return killed


def apply_caps(rule, a, wanted):
    limit = rule["limit_mb"] * MB
    per = max(CAP_MIN, limit // max(1, len(a["pids"])))
    new = fail = 0
    skip = clipboard_pids()
    for pid, _ in a["pids"]:
        if pid in skip:
            continue
        try:
            ct = psutil.Process(pid).create_time()
        except psutil.Error:
            continue
        cur = ST.capped.get(pid)
        if cur and cur[0] == ct and abs(cur[1] - per) / per < 0.1:
            wanted.add(pid)
            continue
        if cap_pid(pid, per):
            ST.capped[pid] = (ct, per)
            wanted.add(pid)
            new += 1
        else:
            fail += 1
    if new:
        log_event("cap", rule["name"], f"Hard cap of {per // MB} MB applied to {new} process(es) (limit {rule['limit_mb']} MB total)")
    elif fail and time.time() - ST.last_cap_warn > 300:
        ST.last_cap_warn = time.time()
        log_event("info", rule["name"], f"Could not cap {fail} process(es) - access denied (try running RamCapper as administrator)")


def run_limiter(now, percent, apps):
    with cfg_lock:
        cfg = json.loads(json.dumps(CFG))
    wanted = set()
    for r in cfg["rules"]:
        if not r["enabled"]:
            continue
        a = apps.get(r["name"])
        if r["action"] == "cap":
            if a:
                apply_caps(r, a, wanted)
            continue
        rid = r["id"]
        if not a or a["rss"] <= r["limit_mb"] * MB:
            ST.breach[rid] = 0
            continue
        ST.breach[rid] = ST.breach.get(rid, 0) + 1
        if now - ST.last_fire.get(rid, 0) < COOLDOWN[r["action"]]:
            continue
        cur = a["rss"] // MB
        if r["action"] == "notify":
            ST.last_fire[rid] = now
            log_event("notify", r["name"], f"{r['name']} is using {cur} MB (limit {r['limit_mb']} MB)")
        elif r["action"] == "trim":
            ST.last_fire[rid] = now
            freed, ok, _ = trim_apps({r["name"]})
            if freed > 10 * MB:
                log_event("trim", r["name"], f"Over limit ({cur} MB > {r['limit_mb']} MB): trimmed {ok} process(es), freed {freed // MB} MB")
        elif r["action"] == "terminate" and ST.breach[rid] >= r["grace"]:
            ST.last_fire[rid] = now
            n = kill_procs([pid for pid, _ in a["pids"]])
            log_event("kill", r["name"], f"Over limit ({cur} MB > {r['limit_mb']} MB) for {r['grace']} checks: terminated {n} process(es)")
    # release caps that are no longer wanted
    for pid in list(ST.capped):
        if pid not in wanted:
            ct = ST.capped.pop(pid)[0]
            try:
                if psutil.Process(pid).create_time() == ct:
                    uncap_pid(pid)
            except psutil.Error:
                pass
    g = cfg["global"]
    if g["enabled"] and percent >= g["threshold"] and now - ST.last_global > g["cooldown"]:
        ST.last_global = now
        before = psutil.virtual_memory().available
        freed, ok, failed = trim_apps()
        gain = max(0, psutil.virtual_memory().available - before)
        log_event("auto", "system", f"RAM at {percent:.0f}% (threshold {g['threshold']}%): trimmed {ok} processes, ~{max(freed, gain) // MB} MB returned to Windows")


def tick():
    now = time.time()
    ms = mem_status()
    apps = collect()
    used = ms.ullTotalPhys - ms.ullAvailPhys
    sysinfo = {
        "total": ms.ullTotalPhys, "used": used, "avail": ms.ullAvailPhys,
        "percent": used / ms.ullTotalPhys * 100,
        "commit_used": ms.ullTotalPageFile - ms.ullAvailPageFile, "commit_limit": ms.ullTotalPageFile,
    }
    with ST.lock:
        ST.sysinfo = sysinfo
        ST.apps = apps
        for k, a in apps.items():
            ST.live.setdefault(k, deque(maxlen=180)).append((now, a["rss"]))
        for k in list(ST.live):
            if k not in apps:
                dq = ST.live[k]
                dq.append((now, 0))
                if not any(v for _, v in list(dq)[-30:]):
                    del ST.live[k]
    if module_on("network"):
        try:
            net_tick(now)
        except Exception as e:
            print("net error:", e, file=sys.stderr)
    try:
        run_limiter(now, sysinfo["percent"], apps)
    except Exception as e:  # never let the limiter kill the sampler
        print("limiter error:", e, file=sys.stderr)
    if now - ST.last_persist >= PERSIST_EVERY:
        ST.last_persist = now
        ts = int(now)
        with cfg_lock:
            ruled = {r["name"] for r in CFG["rules"] if r["enabled"]}
        top = sorted(apps.values(), key=lambda a: a["rss"], reverse=True)[:TOP_STORE]
        keep = {a["name"]: a for a in top}
        for n in ruled:
            if n in apps:
                keep[n] = apps[n]
        with wlock:
            wdb.execute("INSERT INTO sys VALUES(?,?,?,?)", (ts, used, ms.ullTotalPhys, sysinfo["commit_used"]))
            wdb.executemany("INSERT INTO app VALUES(?,?,?,?)", [(ts, a["name"], a["rss"], len(a["pids"])) for a in keep.values()])
            if now - ST.last_prune > 3600:
                ST.last_prune = now
                cut = ts - RETENTION
                wdb.execute("DELETE FROM sys WHERE ts<?", (cut,))
                wdb.execute("DELETE FROM app WHERE ts<?", (cut,))
                wdb.execute("DELETE FROM events WHERE ts<?", (cut,))
            wdb.commit()


def sampler():
    while True:
        t0 = time.time()
        try:
            tick()
        except Exception as e:
            print("sampler error:", e, file=sys.stderr)
        time.sleep(max(0.2, TICK - (time.time() - t0)))


def release_caps():
    for pid in list(ST.capped):
        uncap_pid(pid)


# ---------------------------------------------------------------- queries
def bucket_for(secs):
    return max(5, int(secs / 240) // 5 * 5)


def history(rng, name=None, topn=8):
    secs = RANGES.get(rng, 3600)
    now = int(time.time())
    start = now - secs
    b = bucket_for(secs)
    db = rdb()
    try:
        srows = db.execute("SELECT (ts/?)*? bt, AVG(used) u, MAX(total) tot FROM sys WHERE ts>=? GROUP BY bt ORDER BY bt", (b, b, start)).fetchall()
        t = [r["bt"] for r in srows]
        idx = {bt: i for i, bt in enumerate(t)}
        used = [int(r["u"]) for r in srows]
        series = []
        if name:
            names = [name]
        else:
            names = [r["name"] for r in db.execute("SELECT name FROM app WHERE ts>=? GROUP BY name ORDER BY SUM(rss) DESC LIMIT ?", (start, topn)).fetchall()]
        for n in names:
            vals = [0] * len(t)
            for r in db.execute("SELECT (ts/?)*? bt, AVG(rss) v FROM app WHERE ts>=? AND name=? GROUP BY bt", (b, b, start, n)):
                i = idx.get(r["bt"])
                if i is not None:
                    vals[i] = int(r["v"])
            series.append({"name": n, "v": vals})
        if not name:
            other = []
            for i in range(len(t)):
                other.append(max(0, used[i] - sum(s["v"][i] for s in series)))
            series.append({"name": "other", "v": other})
        events = [dict(r) for r in db.execute("SELECT id,ts,kind,app,detail FROM events WHERE ts>=? ORDER BY ts", (start,))]
        total = max([r["tot"] for r in srows], default=ST.sysinfo.get("total", 0))
        return {"start": start, "end": now, "bucket": b, "t": t, "used": used, "total": total, "series": series, "events": events}
    finally:
        db.close()


# ---------------------------------------------------------------- app icons
import struct
import zlib

shell32 = ctypes.WinDLL("shell32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
VP = ctypes.c_void_p
shell32.ExtractIconExW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(VP), ctypes.POINTER(VP), wintypes.UINT]
user32.GetIconInfo.argtypes = [VP, VP]
user32.DestroyIcon.argtypes = [VP]
user32.GetDC.restype = VP
user32.GetDC.argtypes = [VP]
user32.ReleaseDC.argtypes = [VP, VP]
gdi32.GetObjectW.argtypes = [VP, ctypes.c_int, VP]
gdi32.GetDIBits.argtypes = [VP, VP, wintypes.UINT, wintypes.UINT, VP, VP, wintypes.UINT]
gdi32.DeleteObject.argtypes = [VP]


class ICONINFO(ctypes.Structure):
    _fields_ = [("fIcon", wintypes.BOOL), ("xHotspot", wintypes.DWORD), ("yHotspot", wintypes.DWORD), ("hbmMask", VP), ("hbmColor", VP)]


class BITMAP(ctypes.Structure):
    _fields_ = [("bmType", ctypes.c_long), ("bmWidth", ctypes.c_long), ("bmHeight", ctypes.c_long), ("bmWidthBytes", ctypes.c_long),
                ("bmPlanes", wintypes.WORD), ("bmBitsPixel", wintypes.WORD), ("bmBits", VP)]


class BIH(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", ctypes.c_long), ("biHeight", ctypes.c_long), ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD), ("biSizeImage", wintypes.DWORD),
                ("biXPelsPerMeter", ctypes.c_long), ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]


def _dib(hdc, hbm, w, h):
    bi = BIH(40, w, -h, 1, 32, 0, 0, 0, 0, 0, 0)
    buf = (ctypes.c_ubyte * (w * h * 4))()
    gdi32.GetDIBits(hdc, hbm, 0, h, buf, ctypes.byref(bi), 0)
    return bytearray(buf)


def _png(w, h, rgba):
    raw = b"".join(b"\x00" + bytes(rgba[y * w * 4:(y + 1) * w * 4]) for y in range(h))
    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")


def _extract_icon(path, idx=0):
    large = VP()
    if shell32.ExtractIconExW(path, idx, ctypes.byref(large), None, 1) < 1 or not large:
        return None
    ii = ICONINFO()
    hdc = None
    try:
        if not user32.GetIconInfo(large, ctypes.byref(ii)) or not ii.hbmColor:
            return None
        bm = BITMAP()
        gdi32.GetObjectW(ii.hbmColor, ctypes.sizeof(bm), ctypes.byref(bm))
        w, h = bm.bmWidth, bm.bmHeight
        hdc = user32.GetDC(None)
        px = _dib(hdc, ii.hbmColor, w, h)
        if not any(px[3::4]):                      # no alpha channel: derive it from the mask
            mask = _dib(hdc, ii.hbmMask, w, h) if ii.hbmMask else None
            for i in range(w * h):
                px[i * 4 + 3] = 0 if (mask and mask[i * 4]) else 255
        px[0::4], px[2::4] = px[2::4], px[0::4]    # BGRA -> RGBA
        return _png(w, h, px)
    finally:
        if hdc:
            user32.ReleaseDC(None, hdc)
        if ii.hbmColor:
            gdi32.DeleteObject(ii.hbmColor)
        if ii.hbmMask:
            gdi32.DeleteObject(ii.hbmMask)
        user32.DestroyIcon(large)


ICONS = {}
icon_lock = threading.Lock()


def icon_png(name):
    with icon_lock:
        if name in ICONS:
            return ICONS[name]
        png = None
        a = ST.apps.get(name)
        for pid, _ in (a["pids"] if a else []):
            try:
                png = _extract_icon(psutil.Process(pid).exe())
            except (psutil.Error, OSError):
                png = None
            if png:
                break
        if not png:
            png = ICONS.get("") or _extract_icon(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "shell32.dll"), 2)
            ICONS[""] = png
        ICONS[name] = png
        return png


SELF = psutil.Process()
SELF.cpu_percent(None)
SELF_NAME = SELF.name().lower()
NCPU = psutil.cpu_count() or 1


def self_usage():
    """RamCapper's own footprint (this process plus the onefile bootloader parent when frozen)."""
    procs = [SELF]
    if FROZEN:
        try:
            parent = SELF.parent()
            if parent and parent.name().lower() == SELF.name().lower():
                procs.append(parent)
        except psutil.Error:
            pass
    rss = private = 0
    for p in procs:
        try:
            mi = p.memory_info()
            rss += mi.rss
            private += getattr(mi, "private", mi.rss)
        except psutil.Error:
            pass
    return {"rss": rss, "private": private, "cpu": SELF.cpu_percent(None) / NCPU, "threads": SELF.num_threads(),
            "procs": len(procs), "db": os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0}


def now_payload():
    with ST.lock:
        s = dict(ST.sysinfo)
        apps = sorted(ST.apps.values(), key=lambda a: a["rss"], reverse=True)[:80]
        out = []
        t_ref = time.time() - 300
        for a in apps:
            dq = list(ST.live.get(a["name"], []))
            past = a["rss"]
            for ts, v in dq:
                if ts >= t_ref:
                    past = v
                    break
            vals = [v for _, v in dq[-60:]]
            step = max(1, len(vals) // 30)
            out.append({"name": a["name"], "rss": a["rss"], "private": a["private"], "procs": len(a["pids"]),
                        "d5": a["rss"] - past, "spark": vals[::step],
                        "protected": a["name"] in PROTECTED or a["name"] == SELF_NAME})
    with cfg_lock:
        rules = list(CFG["rules"])
    return {"sys": s, "apps": out, "admin": ADMIN, "self": self_usage(), "ts": time.time(), "capped": len(ST.capped), "rules": rules}


def app_detail(name):
    name = name.lower()
    procs = []
    for p in psutil.process_iter(["pid", "name", "memory_info", "create_time", "cmdline"]):
        try:
            if (p.info["name"] or "").lower() != name or p.info["memory_info"] is None:
                continue
            mi = p.info["memory_info"]
            cmd = " ".join(p.info["cmdline"] or [])[:160]
            procs.append({"pid": p.info["pid"], "rss": mi.rss, "private": getattr(mi, "private", mi.rss),
                          "started": p.info["create_time"], "cmd": cmd, "capped": p.info["pid"] in ST.capped})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda p: p["rss"], reverse=True)
    return {"name": name, "procs": procs, "protected": name in PROTECTED}


# ---------------------------------------------------------------- network module
NOWIN = 0x08000000  # CREATE_NO_WINDOW


class Net:
    rate = deque(maxlen=150)       # (ts, down_bps, up_bps)
    last_io = None
    scanning = False
    last_scan = 0.0
    scan_finished = 0.0
    online = set()
    subnet = ""
    my_ip = ""
    gateway = ""
    rdns = {}
    pending = set()


from concurrent.futures import ThreadPoolExecutor
_rdns_pool = ThreadPoolExecutor(max_workers=4)


def _resolve(ip):
    try:
        Net.rdns[ip] = socket.gethostbyaddr(ip)[0]
    except Exception:
        Net.rdns[ip] = ""
    Net.pending.discard(ip)


def rdns_cached(ip):
    if ip in Net.rdns:
        return Net.rdns[ip]
    if ip not in Net.pending:
        Net.pending.add(ip)
        _rdns_pool.submit(_resolve, ip)
    return ""


def net_tick(now):
    io = psutil.net_io_counters()
    if Net.last_io:
        t0, r0, s0 = Net.last_io
        dt = max(0.1, now - t0)
        Net.rate.append((now, max(0, io.bytes_recv - r0) / dt, max(0, io.bytes_sent - s0) / dt))
    Net.last_io = (now, io.bytes_recv, io.bytes_sent)
    if not Net.scanning and now - Net.last_scan > 120:
        Net.last_scan = now
        threading.Thread(target=net_scan, daemon=True).start()


def scope_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "net"
    if a.is_loopback:
        return "local"
    if a.is_private or a.is_link_local:
        return "lan"
    return "net"


def net_connections():
    names = {}
    out = []
    for c in psutil.net_connections(kind="inet"):
        pid = c.pid or 0
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name() if pid else "System"
            except psutil.Error:
                names[pid] = f"pid {pid}"
        tcp = c.type == socket.SOCK_STREAM
        r = c.raddr
        out.append({
            "proto": "TCP" if tcp else "UDP", "l": c.laddr.ip if c.laddr else "", "lp": c.laddr.port if c.laddr else 0,
            "r": r.ip if r else "", "rp": r.port if r else 0, "st": c.status if tcp else "",
            "pid": pid, "proc": names[pid],
            "scope": scope_of(r.ip) if r else "",
            "host": rdns_cached(r.ip) if r and c.status == "ESTABLISHED" and scope_of(r.ip) == "net" else "",
        })
    return out


def local_net():
    skip = re.compile(r"vethernet|vmware|virtualbox|loopback|bluetooth|wsl|hyper-v|docker", re.I)
    stats = psutil.net_if_stats()
    best = None
    for virt_pass in (False, True):
        for name, addrs in psutil.net_if_addrs().items():
            if not stats.get(name) or not stats[name].isup or (bool(skip.search(name)) and not virt_pass):
                continue
            for a in addrs:
                if a.family == socket.AF_INET and a.netmask and not a.address.startswith(("127.", "169.254.")):
                    net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
                    if net.prefixlen < 24:
                        net = ipaddress.ip_network(f"{a.address}/24", strict=False)
                    mac = next((x.address for x in addrs if x.family == psutil.AF_LINK), "")
                    return a.address, net, mac.lower().replace(":", "-")
        if best:
            break
    return None


def _ping(ip):
    subprocess.run(["ping", "-n", "1", "-w", "300", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=NOWIN)


def _gateway():
    try:
        out = subprocess.check_output(["route", "print", "-4", "0.0.0.0"], text=True, creationflags=NOWIN, timeout=5)
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
        return m.group(1) if m else ""
    except Exception:
        return ""


def net_scan():
    """Ping-sweep the local /24, then read the ARP table to list devices on this network."""
    Net.scanning = True
    try:
        ln = local_net()
        if not ln:
            return
        my_ip, net, my_mac = ln
        Net.my_ip, Net.subnet, Net.gateway = my_ip, str(net), _gateway()
        hosts = [str(h) for h in net.hosts() if str(h) != my_ip]
        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(_ping, hosts))
        out = subprocess.check_output(["arp", "-a"], text=True, creationflags=NOWIN, timeout=10)
        found, section = {}, False
        for line in out.splitlines():
            m = re.match(r"\s*Interface:\s+(\S+)", line)
            if m:
                section = m.group(1) == my_ip
                continue
            m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(\w+)", line, re.I)
            if section and m and m.group(3).lower() == "dynamic":
                ip, mac = m.group(1), m.group(2).lower()
                if ipaddress.ip_address(ip) in net and not mac.startswith("ff-ff") and not mac.startswith("01-00-5e"):
                    found[mac] = ip
        if my_mac:
            found[my_mac] = my_ip
        with ThreadPoolExecutor(max_workers=16) as ex:
            names = dict(zip(found.values(), ex.map(lambda ip: socket.gethostname() if ip == my_ip else _name(ip), found.values())))
        now = int(time.time())
        with wlock:
            known = {r[0] for r in wdb.execute("SELECT mac FROM devices")}
            for mac, ip in found.items():
                if known and mac not in known:
                    log_event_nolock("net", ip, f"New device on your network: {ip} ({mac}){' ' + names[ip] if names[ip] else ''}")
                wdb.execute("INSERT INTO devices(mac,ip,host,first_seen,last_seen) VALUES(?,?,?,?,?) "
                            "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, host=CASE WHEN excluded.host!='' THEN excluded.host ELSE host END, last_seen=excluded.last_seen",
                            (mac, ip, names[ip], now, now))
            wdb.commit()
        Net.online = set(found)
        Net.scan_finished = time.time()
    except Exception as e:
        print("net scan error:", e, file=sys.stderr)
    finally:
        Net.scanning = False


def _name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def log_event_nolock(kind, app, detail):
    wdb.execute("INSERT INTO events(ts,kind,app,detail) VALUES(?,?,?,?)", (int(time.time()), kind, app, detail))


def net_devices():
    db = rdb()
    rows = [dict(r) for r in db.execute("SELECT mac,ip,host,first_seen,last_seen FROM devices")]
    db.close()
    for r in rows:
        r["online"] = r["mac"] in Net.online
        r["random"] = bool(int(r["mac"][:2], 16) & 2)
        r["gateway"] = r["ip"] == Net.gateway
        r["me"] = r["ip"] == Net.my_ip
    rows.sort(key=lambda r: tuple(int(x) for x in r["ip"].split(".")))
    return rows


def net_payload():
    rate = list(Net.rate)
    io = psutil.net_io_counters()
    conns = net_connections()
    return {"conns": conns, "rate": [[round(t), d, u] for t, d, u in rate], "total_down": io.bytes_recv, "total_up": io.bytes_sent,
            "devices": net_devices(), "scanning": Net.scanning, "scan_finished": Net.scan_finished,
            "subnet": Net.subnet, "my_ip": Net.my_ip}


# ---------------------------------------------------------------- storage module
class Scan:
    root = ""
    running = False
    cancel = False
    files = dirs = nbytes = errors = 0
    current = ""
    started = finished = 0.0
    tree = None
    top = []
    types = {}


PRUNE = 1 * MB
REPARSE = 0x400


def _walk(path, name):
    node = {"n": name, "s": 0, "f": 0, "fb": 0, "sm": 0, "c": []}
    Scan.dirs += 1
    Scan.current = path
    try:
        it = os.scandir(path)
    except OSError:
        Scan.errors += 1
        return node
    with it:
        for e in it:
            if Scan.cancel:
                break
            try:
                st = e.stat(follow_symlinks=False)
                if st.st_file_attributes & REPARSE:
                    continue
                if e.is_dir(follow_symlinks=False):
                    ch = _walk(e.path, e.name)
                    node["s"] += ch["s"]
                    node["f"] += ch["f"]
                    if ch["s"] >= PRUNE:
                        node["c"].append(ch)
                    else:
                        node["sm"] += ch["s"]
                else:
                    sz = st.st_size
                    node["s"] += sz
                    node["fb"] += sz
                    node["f"] += 1
                    Scan.files += 1
                    Scan.nbytes += sz
                    ext = os.path.splitext(e.name)[1].lower() or "(none)"
                    t = Scan.types.get(ext)
                    if t:
                        t[0] += sz
                        t[1] += 1
                    else:
                        Scan.types[ext] = [sz, 1]
                    if len(Scan.top) < 200:
                        heapq.heappush(Scan.top, (sz, e.path))
                    elif sz > Scan.top[0][0]:
                        heapq.heapreplace(Scan.top, (sz, e.path))
            except OSError:
                Scan.errors += 1
    node["c"].sort(key=lambda c: c["s"], reverse=True)
    return node


def start_scan(root):
    if Scan.running:
        return False
    Scan.root, Scan.running, Scan.cancel = root, True, False
    Scan.files = Scan.dirs = Scan.nbytes = Scan.errors = 0
    Scan.tree, Scan.top, Scan.types = None, [], {}
    Scan.started, Scan.finished = time.time(), 0.0

    def run():
        try:
            Scan.tree = _walk(root, root)
        finally:
            Scan.running = False
            Scan.finished = time.time()
    threading.Thread(target=run, daemon=True).start()
    return True


def free_scan():
    Scan.cancel = True
    if not Scan.running:
        Scan.tree, Scan.top, Scan.types = None, [], {}


def scan_status():
    return {"root": Scan.root, "running": Scan.running, "files": Scan.files, "dirs": Scan.dirs, "bytes": Scan.nbytes,
            "errors": Scan.errors, "current": Scan.current if Scan.running else "", "started": Scan.started,
            "finished": Scan.finished, "has_result": Scan.tree is not None}


def scan_node(path):
    node = Scan.tree
    if node is None:
        return None
    for part in [p for p in path.split("|") if p]:
        node = next((c for c in node["c"] if c["n"] == part), None)
        if node is None:
            return None
    return {"n": node["n"], "s": node["s"], "f": node["f"], "fb": node["fb"], "sm": node["sm"],
            "c": [{"n": c["n"], "s": c["s"], "f": c["f"], "has": bool(c["c"])} for c in node["c"][:300]]}


def drives():
    out = []
    for p in psutil.disk_partitions(all=False):
        if "cdrom" in p.opts or not p.fstype:
            continue
        try:
            u = psutil.disk_usage(p.mountpoint)
            out.append({"path": p.mountpoint, "fs": p.fstype, "total": u.total, "used": u.used, "free": u.free})
        except OSError:
            pass
    return out


SERVER = {}


def quit_app():
    """Release hard caps, flush the DB and exit the whole process."""
    try:
        release_caps()
        with wlock:
            wdb.commit()
            wdb.close()
    finally:
        os._exit(0)


# ---------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    server_version = "RamCapper"

    def log_message(self, *a):
        pass

    def _host_ok(self):
        return self.headers.get("Host", "") in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if u.path == "/api/icon":
                png = icon_png(q.get("name", "").lower())
                if not png:
                    return self._send(404, {"error": "no icon"})
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(png)))
                self.send_header("Cache-Control", "private, max-age=3600")
                self.end_headers()
                self.wfile.write(png)
                return
            if u.path == "/api/now":
                return self._send(200, now_payload())
            if u.path == "/api/history":
                return self._send(200, history(q.get("range", "1h"), q.get("name") or None))
            if u.path == "/api/app":
                return self._send(200, app_detail(q.get("name", "")))
            if u.path == "/api/events":
                db = rdb()
                rows = [dict(r) for r in db.execute("SELECT id,ts,kind,app,detail FROM events ORDER BY id DESC LIMIT 200")]
                db.close()
                return self._send(200, rows)
            if u.path == "/api/config":
                with cfg_lock:
                    return self._send(200, CFG)
            if u.path == "/api/info":
                try:
                    size = os.path.getsize(DB_PATH)
                except OSError:
                    size = 0
                return self._send(200, {"admin": ADMIN, "data_dir": DATA_DIR, "data_source": DATA_SOURCE, "app_dir": APP_DIR,
                                        "db_size": size, "frozen": FROZEN, "port": PORT})
            if u.path == "/api/net":
                if not module_on("network"):
                    return self._send(409, {"error": "network module is off"})
                return self._send(200, net_payload())
            if u.path.startswith("/api/storage/"):
                if not module_on("storage"):
                    return self._send(409, {"error": "storage module is off"})
                what = u.path.rsplit("/", 1)[1]
                if what == "drives":
                    return self._send(200, drives())
                if what == "status":
                    return self._send(200, scan_status())
                if what == "node":
                    n = scan_node(q.get("p", ""))
                    return self._send(200 if n else 404, n or {"error": "no result"})
                if what == "summary":
                    types = sorted(Scan.types.items(), key=lambda kv: kv[1][0], reverse=True)[:15]
                    return self._send(200, {"top": [{"path": p, "size": s} for s, p in sorted(Scan.top, reverse=True)[:100]],
                                            "types": [{"ext": k, "bytes": v[0], "count": v[1]} for k, v in types]})
        except Exception as e:
            return self._send(500, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-RamCapper") != "1":
            return self._send(403, {"error": "forbidden"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            path = urlparse(self.path).path
            if path == "/api/config":
                global CFG
                new = clean_cfg(body)
                with cfg_lock:
                    new["modules"] = CFG.get("modules", dict(DEFAULT_CFG["modules"]))
                    CFG = new
                    save_cfg()
                return self._send(200, new)
            if path == "/api/module":
                name = body.get("name")
                if name not in MODULES:
                    return self._send(400, {"error": "unknown module"})
                on = bool(body.get("enabled"))
                with cfg_lock:
                    CFG.setdefault("modules", {})[name] = on
                    save_cfg()
                if not on:
                    if name == "network":
                        Net.last_io = None
                        Net.rate.clear()
                        Net.last_scan = 0.0
                    else:
                        free_scan()
                return self._send(200, CFG["modules"])
            if path == "/api/net/scan":
                if not module_on("network"):
                    return self._send(409, {"error": "network module is off"})
                if not Net.scanning:
                    Net.last_scan = time.time()
                    threading.Thread(target=net_scan, daemon=True).start()
                return self._send(200, {})
            if path == "/api/storage/scan":
                if not module_on("storage"):
                    return self._send(409, {"error": "storage module is off"})
                root = os.path.abspath(str(body.get("root", "")))
                if not os.path.isdir(root):
                    return self._send(400, {"error": "folder not found"})
                return self._send(200, {"started": start_scan(root)})
            if path == "/api/storage/cancel":
                Scan.cancel = True
                return self._send(200, {})
            if path == "/api/elevate":
                if ADMIN:
                    return self._send(400, {"error": "already running as administrator"})
                if not relaunch_elevated(["--takeover", "--no-open"]):   # blocks on the UAC prompt
                    return self._send(400, {"error": "Administrator permission was not granted"})
                self._send(200, {"ok": True})
                threading.Timer(0.5, quit_app).start()
                return
            if path == "/api/relocate":
                if DATA_SOURCE in ("arg", "env"):
                    return self._send(400, {"error": "The data folder is fixed by the --data option or RAMCAPPER_DATA variable this copy was started with"})
                target = APP_DIR if body.get("reset") else str(body.get("path", "")).strip()
                if not target:
                    return self._send(400, {"error": "Enter a folder path"})
                try:
                    dest, note = relocate(target)
                except (OSError, ValueError) as e:
                    return self._send(400, {"error": str(e)})
                self._send(200, {"dest": dest, "note": note})
                restart_into(lambda: relaunch_normal(["--takeover", "--no-open"], keep_data=False))
                return
            if path == "/api/quit":
                self._send(200, {"bye": True})
                threading.Timer(0.4, quit_app).start()
                return
            if path == "/api/reveal":
                p = os.path.abspath(str(body.get("path", "")))
                root = os.path.abspath(Scan.root) if Scan.root else ""
                if not root or os.path.commonpath([p, root]) != root or not os.path.exists(p):
                    return self._send(400, {"error": "path not in last scan"})
                subprocess.Popen(["explorer", f"/select,{p}"])
                return self._send(200, {})
            if path == "/api/trim":
                keys = {body["name"].lower()} if body.get("name") else None
                if body.get("pid"):
                    ok = int(body["pid"]) not in clipboard_pids() and trim_pid(int(body["pid"]))
                    return self._send(200, {"freed": 0, "ok": int(ok), "failed": int(not ok)})
                freed, ok, failed = trim_apps(keys)
                log_event("trim", body.get("name") or "system", f"Manual trim: {ok} process(es), freed {freed // MB} MB" + (f" ({failed} not accessible)" if failed else ""))
                return self._send(200, {"freed": freed, "ok": ok, "failed": failed})
            if path == "/api/kill":
                if body.get("pid"):
                    pids = [int(body["pid"])]
                    name = "pid %d" % pids[0]
                else:
                    name = body["name"].lower()
                    pids = [p.pid for p in psutil.process_iter(["name"]) if (p.info["name"] or "").lower() == name]
                if name in PROTECTED or name == SELF_NAME:
                    return self._send(400, {"error": "protected process"})
                n_killed = kill_procs(pids)
                log_event("kill", name, f"Manually ended {n_killed} process(es)")
                return self._send(200, {"killed": n_killed})
        except Exception as e:
            return self._send(500, {"error": str(e)})
        self._send(404, {"error": "not found"})


def open_window():
    url = f"http://127.0.0.1:{PORT}/"
    for exe in (shutil.which("msedge"),
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                shutil.which("chrome"),
                r"C:\Program Files\Google\Chrome\Application\chrome.exe"):
        if exe and os.path.exists(exe):
            subprocess.Popen([exe, f"--app={url}", "--window-size=1320,900"])
            return
    webbrowser.open(url)


ADMIN = is_admin()


class Server(ThreadingHTTPServer):
    allow_reuse_address = False   # on Windows SO_REUSEADDR lets a second copy bind the same port


def single_instance():
    """Named mutex: False when another RamCapper (even an elevated one) already owns it."""
    k32.CreateMutexW.restype = wintypes.HANDLE
    k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    h = k32.CreateMutexW(None, False, f"RamCapper-single-instance-{PORT}")
    err = ctypes.get_last_error()
    if not h:
        return False                       # ACCESS_DENIED: owned by a copy running at a higher level
    if err == 183:                         # ALREADY_EXISTS - drop our handle so the old owner's exit frees the name
        k32.CloseHandle(h)
        return False
    single_instance.handle = h             # keep alive for the process lifetime
    return True


def _relaunch_args(extra, keep_data):
    args = [a for a in (sys.argv[1:] if FROZEN else sys.argv) if a not in ("--admin", "--takeover", "--no-open")]
    if not keep_data:                      # drop --data so a freshly written pointer file takes effect
        out, skip = [], False
        for a in args:
            if skip:
                skip = False
            elif a == "--data":
                skip = True
            elif not a.startswith("--data="):
                out.append(a)
        args = out
    return args + extra


def relaunch_elevated(extra=(), keep_data=True):
    """Start an elevated copy (UAC prompt). Returns True if the user accepted."""
    args = subprocess.list2cmdline(_relaunch_args(list(extra), keep_data))
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1) > 32


def relaunch_normal(extra=(), keep_data=True):
    env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1")
    subprocess.Popen([sys.executable] + _relaunch_args(list(extra), keep_data), env=env, close_fds=True,
                     creationflags=0x00000008 | 0x00000200)   # DETACHED_PROCESS | NEW_PROCESS_GROUP


# ---- data folder relocation
def set_pointer(path):
    for p in POINTERS:
        try:
            os.remove(p)
        except OSError:
            pass
    if os.path.normcase(path) == os.path.normcase(APP_DIR):
        return
    for p in POINTERS:
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(path)
            return
        except OSError:
            continue
    raise OSError("could not save the data folder setting")


def relocate(path):
    """Copy history + config into `path` (never overwriting existing data there), point RamCapper at it."""
    dest = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
    if os.path.normcase(dest) == os.path.normcase(DATA_DIR):
        raise ValueError("That is already the current data folder")
    os.makedirs(dest, exist_ok=True)
    probe = os.path.join(dest, ".ramcapper_write_test")
    with open(probe, "w") as f:
        f.write("x")
    os.remove(probe)
    note = []
    dst_db, dst_cfg = os.path.join(dest, "history.db"), os.path.join(dest, "config.json")
    if os.path.exists(dst_db):
        note.append("kept the history already in that folder")
    else:
        with wlock:
            out = sqlite3.connect(dst_db)
            wdb.backup(out)
            out.close()
    if not os.path.exists(dst_cfg):
        with cfg_lock:
            save_cfg()
        shutil.copy2(CFG_PATH, dst_cfg)
    set_pointer(dest)
    return dest, note


def restart_into(fn):
    """Spawn the replacement copy, then exit; the new copy waits (--takeover) until this one has gone."""
    fn()
    threading.Timer(0.5, quit_app).start()


def main():
    no_open = "--no-open" in sys.argv
    takeover = "--takeover" in sys.argv
    if "--admin" in sys.argv and not ADMIN:
        relaunch_elevated()
        return
    deadline = time.time() + (25 if takeover else 0)
    while True:                            # takeover: wait for the previous copy to release the mutex/port
        if single_instance():
            try:
                srv = Server(("127.0.0.1", PORT), Handler)
                break
            except OSError:
                k32.CloseHandle(single_instance.handle)
        if time.time() >= deadline:
            if not no_open:
                open_window()              # already running - just show its window
            return
        time.sleep(0.4)
    SERVER["srv"] = srv
    atexit.register(release_caps)
    threading.Thread(target=sampler, daemon=True).start()
    if not no_open:
        threading.Timer(1.0, open_window).start()
    print(f"RamCapper running on http://127.0.0.1:{PORT}  (admin={ADMIN})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
