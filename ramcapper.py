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

try:                                    # before any window exists, so the notch is drawn at native resolution
    ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))      # per-monitor v2
except Exception:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass

VERSION = "1.5.0"
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
for _col in ("vendor", "kind", "label"):     # devices table grew these columns after v1.0
    try:
        wdb.execute(f"ALTER TABLE devices ADD COLUMN {_col} TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
wdb.commit()


def rdb():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def log_event(kind, app, detail):
    with wlock:
        wdb.execute("INSERT INTO events(ts,kind,app,detail) VALUES(?,?,?,?)", (int(time.time()), kind, app, detail))
        wdb.commit()
    if kind != "info":
        try:
            pill_flash(f"{app}: {detail}")
        except NameError:
            pass


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
        c.setdefault("netrules", [])
        c.setdefault("minibar", "minimized")
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
    ident_done = {}
    force_ident = False


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
    bw_tick(now)
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


# ---- device identification: vendor database, DNS/mDNS/NetBIOS/SSDP lookups and a light port fingerprint
import gzip
import random
import urllib.request
from urllib.parse import urlparse as _urlparse

_OUI = None


def oui_vendor(mac):
    global _OUI
    if _OUI is None:
        try:
            with gzip.open(os.path.join(HERE, "assets", "oui.json.gz"), "rt", encoding="utf-8") as f:
                _OUI = json.load(f)
        except Exception:
            _OUI = {}
    return _OUI.get(mac.replace("-", "")[:6].lower(), "")


def _read_name(b, o):
    parts, end, jumped = [], 0, False
    for _ in range(64):
        n = b[o]
        if n == 0:
            o += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end, jumped = o + 2, True
            o = ((n & 0x3F) << 8) | b[o + 1]
            continue
        parts.append(b[o + 1:o + 1 + n].decode("utf-8", "replace"))
        o += 1 + n
    else:
        raise ValueError("name loop")
    return ".".join(parts), (end if jumped else o)


def _ptr_query(ip, server, port, timeout=1.0, mdns=False):
    """Reverse-DNS (PTR) lookup of `ip` sent straight to `server`:`port` (a DNS server, or the device itself for mDNS)."""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    qid = 0 if mdns else random.randint(1, 65535)
    pkt = struct.pack(">HHHHHH", qid, 0 if mdns else 0x0100, 1, 0, 0, 0)
    pkt += b"".join(bytes([len(p)]) + p.encode() for p in rev.split(".")) + b"\x00"
    pkt += struct.pack(">HH", 12, 0x8001 if mdns else 1)   # 0x8001 = IN + unicast-response bit
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, port))
        resp, _ = s.recvfrom(2048)
    finally:
        s.close()
    qd, an = struct.unpack(">HH", resp[4:8])
    o = 12
    for _ in range(qd):
        _, o = _read_name(resp, o)
        o += 4
    for _ in range(an):
        _, o = _read_name(resp, o)
        t, _c, _ttl, rl = struct.unpack(">HHIH", resp[o:o + 10])
        o += 10
        if t == 12:
            return _read_name(resp, o)[0]
        o += rl
    return ""


def _nbstat(ip, timeout=1.0):
    """NetBIOS name query (UDP 137): answered by Windows PCs, NAS boxes, printers, some Android/Samba devices."""
    enc = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 15)]) for c in b"*" + b"\x00" * 15)
    pkt = struct.pack(">HHHHHH", random.randint(1, 65535), 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack(">HH", 0x21, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        resp, _ = s.recvfrom(2048)
    finally:
        s.close()
    _, o = _read_name(resp, 12)
    o += 10
    for i in range(resp[o]):
        e = resp[o + 1 + i * 18:o + 1 + (i + 1) * 18]
        if e[15] == 0 and not (e[16] & 0x80):    # unique workstation name
            return e[:15].decode("ascii", "replace").strip()
    return ""


def _ssdp(my_ip, wait=2.5):
    """UPnP discovery: smart TVs, consoles, speakers, routers, printers answer with a description URL."""
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.bind((my_ip, 0))
        s.settimeout(0.4)
        msg = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                continue
            hdr = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdr[k.strip().lower()] = v.strip()
            d = found.setdefault(addr[0], {})
            d.setdefault("location", hdr.get("location", ""))
            d.setdefault("server", hdr.get("server", ""))
    except OSError:
        pass
    finally:
        s.close()
    return found


def _upnp_info(ip, location):
    """friendlyName / manufacturer / model from the device's own description XML (only fetched from the device itself)."""
    try:
        u = _urlparse(location)
        if u.scheme != "http" or u.hostname != ip:
            return {}
        with urllib.request.urlopen(location, timeout=2) as r:
            xml = r.read(65536).decode("utf-8", "replace")
        g = lambda tag: (re.search(rf"<{tag}>([^<]{{1,80}})</{tag}>", xml) or [None, ""])[1].strip()
        return {"name": g("friendlyName"), "maker": g("manufacturer"), "model": g("modelName")}
    except Exception:
        return {}


def _http_title(ip):
    try:
        with urllib.request.urlopen(f"http://{ip}/", timeout=1.5) as r:
            html_ = r.read(16384).decode("utf-8", "replace")
        m = re.search(r"<title[^>]*>([^<]{1,60})</title>", html_, re.I)
        t = (m.group(1).strip() if m else "")
        return "" if re.fullmatch(r"(index|home|login|welcome|untitled)?( page)?", t, re.I) else t
    except Exception:
        return ""


PROBE_PORTS = (22, 80, 443, 445, 3389, 5000, 8008, 8009, 8080, 9100, 515, 554, 62078)
VENDOR_KINDS = (("apple", "Apple device"), ("samsung", "Samsung device"), ("espressif", "Smart-home / IoT device"),
                ("raspberry", "Raspberry Pi"), ("amazon", "Amazon device (Echo / Fire)"), ("google", "Google / Nest device"),
                ("sonos", "Sonos speaker"), ("roku", "Roku streamer"), ("nintendo", "Nintendo console"), ("sony", "Sony device"),
                ("microsoft", "Microsoft device"), ("xiaomi", "Xiaomi device"), ("huawei", "Huawei device"), ("tp-link", "Network equipment"),
                ("netgear", "Network equipment"), ("ubiquiti", "Network equipment"), ("zyxel", "Network equipment"), ("d-link", "Network equipment"),
                ("tuya", "Smart-home / IoT device"), ("meross", "Smart plug / IoT device"), ("ring", "Ring camera / doorbell"),
                ("high-flying", "IoT Wi-Fi module"), ("icomm", "IoT Wi-Fi module"), ("shelly", "Smart-home / IoT device"),
                ("wyze", "Wyze camera / IoT"), ("eufy", "Eufy / Anker device"), ("philips", "Philips device (Hue / TV)"), ("hikvision", "IP camera"), ("dahua", "IP camera"), ("lg ", "LG device (TV / phone)"),
                ("intel", "Computer"), ("realtek", "Computer / network adapter"), ("hewlett", "HP device / printer"), ("canon", "Printer"),
                ("epson", "Printer"), ("brother", "Printer"), ("vmware", "Virtual machine"))


def _guess_kind(ports, vendor, host, ssdp_model, is_gw, is_me, random_mac):
    v, h = vendor.lower() + " ", host.lower()
    if is_me:
        return "This PC"
    if is_gw:
        return "Router / gateway"
    if 62078 in ports or "iphone" in h or "ipad" in h:
        return "iPhone / iPad"
    if 8008 in ports or 8009 in ports or "chromecast" in (h + ssdp_model.lower()):
        return "Chromecast / Google TV"
    if 9100 in ports or 515 in ports:
        return "Printer"
    if 554 in ports:
        return "IP camera / recorder"
    for key, label in VENDOR_KINDS:
        if re.search(r"\b" + re.escape(key.strip()) + r"\b", v):
            return label
    if 3389 in ports or 445 in ports:
        return "Windows PC / file server"
    if 5000 in ports:
        return "NAS / media server"
    if 22 in ports:
        return "Linux / SSH device"
    if random_mac:
        return "Phone / laptop (private MAC)"
    if {80, 443, 8080} & set(ports):
        return "Device with a web page"
    return ""


def _clean_host(n):
    n = (n or "").strip().rstrip(".")
    if len(n) < 3 or re.fullmatch(r"[\d.]+(\.in-addr\.arpa)?", n):
        return ""
    return re.sub(r"\.(local|lan|home|localdomain|fritz\.box|router|internal|gateway)$", "", n, flags=re.I)[:48]


def identify(mac, ip, my_ip, gateway, ssdp):
    """Best-effort name/vendor/kind for one device. Every lookup is optional and bounded by short timeouts."""
    info = {"host": "", "vendor": oui_vendor(mac), "kind": ""}
    me = ip == my_ip
    host, model = "", ""
    if me:
        host = socket.gethostname()
    else:
        for fn in (lambda: _nbstat(ip),                                             # Windows / Samba / NAS
                   lambda: _ptr_query(ip, ip, 5353, 1.0, mdns=True),                 # Apple, many Android, Linux (Bonjour/Avahi)
                   lambda: _ptr_query(ip, gateway, 53, 1.0) if gateway else "",      # router DNS often knows DHCP hostnames
                   lambda: socket.gethostbyaddr(ip)[0]):                             # system resolver
            try:
                host = _clean_host(fn())
            except Exception:
                host = ""
            if host:
                break
    ports = []
    if not me:
        for p in PROBE_PORTS:
            s = socket.socket()
            s.settimeout(0.3)
            try:
                if s.connect_ex((ip, p)) == 0:
                    ports.append(p)
            except OSError:
                pass
            finally:
                s.close()
    up = _upnp_info(ip, ssdp[ip]["location"]) if ssdp.get(ip, {}).get("location") else {}
    model = " ".join(x for x in (up.get("maker"), up.get("model")) if x)
    if not host and up.get("name"):
        host = _clean_host(up["name"])
    title = _http_title(ip) if (not me and 80 in ports) else ""
    if not info["vendor"] and up.get("maker"):
        info["vendor"] = up["maker"][:40]
    info["host"] = host
    info["kind"] = _guess_kind(ports, info["vendor"], host, model, ip == gateway, me, bool(int(mac[:2], 16) & 2))
    if model and info["kind"] in ("", "Device with a web page"):
        info["kind"] = model[:48]
    elif title and len(title) > 3 and info["kind"] in ("", "Device with a web page"):
        info["kind"] = ("Web page: " + title)[:48]
    return info


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
        now = int(time.time())
        with wlock:
            old = {r[0]: r[1] for r in wdb.execute("SELECT mac,host FROM devices")}
        # deep identification (DNS/mDNS/NetBIOS/UPnP/ports) only for new or still-unnamed devices, or on a manual scan
        due = [m for m in found if Net.force_ident or m not in Net.ident_done or (now - Net.ident_done[m] > 1800 and not old.get(m))]
        ssdp = _ssdp(my_ip) if due else {}

        def safe_identify(m):
            try:
                return identify(m, found[m], my_ip, Net.gateway, ssdp)
            except Exception:
                return {"host": "", "vendor": oui_vendor(m), "kind": ""}
        with ThreadPoolExecutor(max_workers=16) as ex:
            res = dict(zip(due, ex.map(safe_identify, due)))
        for m in due:
            Net.ident_done[m] = now
        Net.force_ident = False
        with wlock:
            known = set(old)
            for mac, ip in found.items():
                r = res.get(mac) or {"host": "", "vendor": oui_vendor(mac), "kind": ""}
                if known and mac not in known:
                    log_event_nolock("net", ip, f"New device on your network: {ip} ({mac}) {r['host'] or r['vendor'] or ''}".rstrip())
                wdb.execute("INSERT INTO devices(mac,ip,host,vendor,kind,first_seen,last_seen) VALUES(?,?,?,?,?,?,?) "
                            "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, last_seen=excluded.last_seen, "
                            "host=CASE WHEN excluded.host!='' THEN excluded.host ELSE host END, "
                            "vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE vendor END, "
                            "kind=CASE WHEN excluded.kind!='' THEN excluded.kind ELSE kind END",
                            (mac, ip, r["host"], r["vendor"], r["kind"], now, now))
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
    rows = [dict(r) for r in db.execute("SELECT mac,ip,host,vendor,kind,label,first_seen,last_seen FROM devices")]
    db.close()
    for r in rows:
        r["online"] = r["mac"] in Net.online
        r["random"] = bool(int(r["mac"][:2], 16) & 2)
        r["gateway"] = r["ip"] == Net.gateway
        r["me"] = r["ip"] == Net.my_ip
    rows.sort(key=lambda r: tuple(int(x) for x in r["ip"].split(".")))
    return rows



# ---- per-app bandwidth: ETW "Microsoft-Windows-Kernel-Network" (TCP + UDP, IPv4 + IPv6). Windows only lets administrators
# start the trace, so without admin the Network page shows connection counts only.
class BW:
    NAME = "RamCapperNet"
    started = False
    error = ""
    handle = 0
    lock = threading.Lock()
    pid_bytes = {}          # pid -> [rx, tx] cumulative since the trace started
    last = {}               # pid -> (rx, tx) at the previous tick
    names = {}              # pid -> exe name
    rates = {}              # exe name -> [down B/s, up B/s]
    totals = {}             # exe name -> [rx, tx] since the trace started
    last_t = 0.0
    keep = None             # keeps ctypes callbacks alive


def _bw_defs():
    from ctypes import Structure, c_ulong, c_ulonglong, c_longlong, c_ushort, c_ubyte, c_long, c_void_p, c_wchar_p, POINTER

    class GUID(Structure):
        _fields_ = [("a", c_ulong), ("b", c_ushort), ("c", c_ushort), ("d", c_ubyte * 8)]

    class WNODE(Structure):
        _fields_ = [("BufferSize", c_ulong), ("ProviderId", c_ulong), ("Historical", c_ulonglong), ("TimeStamp", c_longlong),
                    ("Guid", GUID), ("ClientContext", c_ulong), ("Flags", c_ulong)]

    class PROPS(Structure):
        _fields_ = [("Wnode", WNODE), ("BufferSize", c_ulong), ("MinimumBuffers", c_ulong), ("MaximumBuffers", c_ulong),
                    ("MaximumFileSize", c_ulong), ("LogFileMode", c_ulong), ("FlushTimer", c_ulong), ("EnableFlags", c_ulong),
                    ("AgeLimit", c_long), ("NumberOfBuffers", c_ulong), ("FreeBuffers", c_ulong), ("EventsLost", c_ulong),
                    ("BuffersWritten", c_ulong), ("LogBuffersLost", c_ulong), ("RealTimeBuffersLost", c_ulong),
                    ("LoggerThreadId", c_void_p), ("LogFileNameOffset", c_ulong), ("LoggerNameOffset", c_ulong)]

    class EVENT_TRACE(Structure):
        _fields_ = [("Header", c_ubyte * 48), ("InstanceId", c_ulong), ("ParentInstanceId", c_ulong), ("ParentGuid", GUID),
                    ("MofData", c_void_p), ("MofLength", c_ulong), ("ClientContext", c_ulong)]

    class LOGFILE_HEADER(Structure):
        _fields_ = [("BufferSize", c_ulong), ("Version", c_ulong), ("ProviderVersion", c_ulong), ("NumberOfProcessors", c_ulong),
                    ("EndTime", c_longlong), ("TimerResolution", c_ulong), ("MaximumFileSize", c_ulong), ("LogFileMode", c_ulong),
                    ("BuffersWritten", c_ulong), ("LogInstanceGuid", GUID), ("LoggerName", c_wchar_p), ("LogFileName", c_wchar_p),
                    ("TimeZone", c_ubyte * 172), ("BootTime", c_longlong), ("PerfFreq", c_longlong), ("StartTime", c_longlong),
                    ("ReservedFlags", c_ulong), ("BuffersLost", c_ulong)]

    class EVENT_RECORD(Structure):
        _fields_ = [("Size", c_ushort), ("HeaderType", c_ushort), ("Flags", c_ushort), ("EventProperty", c_ushort),
                    ("ThreadId", c_ulong), ("ProcessId", c_ulong), ("TimeStamp", c_longlong), ("Provider", GUID),
                    ("Id", c_ushort), ("Version", c_ubyte), ("Channel", c_ubyte), ("Level", c_ubyte), ("Opcode", c_ubyte),
                    ("Task", c_ushort), ("Keyword", c_ulonglong), ("Processor", c_ulonglong), ("Activity", GUID),
                    ("BufferContext", c_ulong), ("ExtendedDataCount", c_ushort), ("UserDataLength", c_ushort),
                    ("ExtendedData", c_void_p), ("UserData", c_void_p), ("UserContext", c_void_p)]

    CB = ctypes.WINFUNCTYPE(None, POINTER(EVENT_RECORD))

    class LOGFILE(Structure):
        _fields_ = [("LogFileName", c_wchar_p), ("LoggerName", c_wchar_p), ("CurrentTime", c_longlong), ("BuffersRead", c_ulong),
                    ("ProcessTraceMode", c_ulong), ("CurrentEvent", EVENT_TRACE), ("LogfileHeader", LOGFILE_HEADER),
                    ("BufferCallback", c_void_p), ("BufferSize", c_ulong), ("Filled", c_ulong), ("EventsLost", c_ulong),
                    ("EventRecordCallback", CB), ("IsKernelTrace", c_ulong), ("Context", c_void_p)]
    return GUID, PROPS, LOGFILE, CB, EVENT_RECORD


_BW_SEND = {10, 26, 42, 58}
_BW_RECV = {11, 27, 43, 59}


def _bw_on_event(rec_p):
    try:
        r = rec_p.contents
        i = r.Id
        send = i in _BW_SEND
        if not send and i not in _BW_RECV:
            return
        n = r.UserDataLength
        if n < 8:
            return
        d = ctypes.string_at(r.UserData, min(n, 48))
        pid, size = struct.unpack_from("<II", d, 0)
        v6 = i in (26, 27, 58, 59)
        daddr = d[8:24] if v6 else d[8:12]
        if (not v6 and daddr[0] == 127) or (v6 and daddr == b"\x00" * 15 + b"\x01"):
            return                                                    # loopback is not network traffic
        with BW.lock:
            e = BW.pid_bytes.setdefault(pid, [0, 0])
            e[1 if send else 0] += size
    except Exception:
        pass


def bw_start():
    """Start the ETW session (admin only). Sets BW.error when it cannot run."""
    if BW.started:
        return
    if not ADMIN:
        BW.error = "admin"
        return
    try:
        GUID, PROPS, LOGFILE, CB, EVENT_RECORD = _bw_defs()
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        for fn in ("StartTraceW", "ControlTraceW", "EnableTraceEx2", "ProcessTrace", "CloseTrace"):
            getattr(adv, fn).restype = ctypes.c_ulong
        adv.OpenTraceW.restype = ctypes.c_ulonglong
        adv.OpenTraceW.argtypes = [ctypes.POINTER(LOGFILE)]
        adv.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
        adv.CloseTrace.argtypes = [ctypes.c_ulonglong]
        adv.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_wchar_p, ctypes.c_void_p]
        adv.ControlTraceW.argtypes = [ctypes.c_ulonglong, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong]
        adv.EnableTraceEx2.argtypes = [ctypes.c_ulonglong, ctypes.POINTER(GUID), ctypes.c_ulong, ctypes.c_ubyte,
                                       ctypes.c_ulonglong, ctypes.c_ulonglong, ctypes.c_ulong, ctypes.c_void_p]
        size = ctypes.sizeof(PROPS) + 2 * 64
        buf = ctypes.create_string_buffer(size)
        props = PROPS.from_buffer(buf)

        def init():
            ctypes.memset(buf, 0, size)
            props.Wnode.BufferSize = size
            props.Wnode.Flags = 0x00020000          # WNODE_FLAG_TRACED_GUID
            props.Wnode.ClientContext = 1
            props.LogFileMode = 0x00000100          # EVENT_TRACE_REAL_TIME_MODE
            props.LoggerNameOffset = ctypes.sizeof(PROPS)
        init()
        adv.ControlTraceW(0, BW.NAME, buf, 1)       # stop a session left behind by a crashed copy
        init()
        h = ctypes.c_ulonglong(0)
        err = adv.StartTraceW(ctypes.byref(h), BW.NAME, buf)
        if err:
            BW.error = f"StartTrace failed ({err})"
            return
        prov = GUID(0x7DD42A49, 0x5329, 0x4832, (ctypes.c_ubyte * 8)(0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88))
        err = adv.EnableTraceEx2(h.value, ctypes.byref(prov), 1, 5, 0xFFFFFFFFFFFFFFFF, 0, 0, None)
        if err:
            adv.ControlTraceW(h.value, None, buf, 1)
            BW.error = f"EnableTrace failed ({err})"
            return
        cb = CB(_bw_on_event)
        lf = LOGFILE()
        lf.LoggerName = BW.NAME
        lf.ProcessTraceMode = 0x00000100 | 0x10000000      # real time | event records
        lf.EventRecordCallback = cb
        th = adv.OpenTraceW(ctypes.byref(lf))
        if th in (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF):
            adv.ControlTraceW(h.value, None, buf, 1)
            BW.error = "OpenTrace failed"
            return
        BW.keep = (cb, lf, buf, props, adv)
        BW.handle = h.value
        hh = ctypes.c_ulonglong(th)
        threading.Thread(target=lambda: adv.ProcessTrace(ctypes.byref(hh), 1, None, None), daemon=True).start()
        BW.started = True
        BW.error = ""
        BW.last_t = time.time()
        atexit.register(bw_stop)
    except Exception as e:
        BW.error = f"{type(e).__name__}: {e}"


def bw_stop():
    if not BW.started:
        return
    BW.started = False
    try:
        adv, buf = BW.keep[4], BW.keep[2]
        adv.ControlTraceW(BW.handle, None, buf, 1)
    except Exception:
        pass
    with BW.lock:
        BW.pid_bytes.clear()
    BW.last = {}
    BW.rates, BW.totals = {}, {}


def _bw_name(pid):
    n = BW.names.get(pid)
    if n is None:
        try:
            n = psutil.Process(pid).name() if pid else "System"
        except psutil.Error:
            n = f"pid {pid}"
        BW.names[pid] = n
    return n


def bw_tick(now):
    """Turn the cumulative per-PID counters into per-app rates (called every sampler tick)."""
    if not BW.started:
        bw_start()
        return
    dt = max(0.2, now - BW.last_t)
    BW.last_t = now
    with BW.lock:
        snap = {pid: tuple(v) for pid, v in BW.pid_bytes.items()}
    rates, tot = {}, {}
    for pid, (rx, tx) in snap.items():
        a = _bw_name(pid)
        t = tot.setdefault(a, [0, 0])
        t[0] += rx
        t[1] += tx
        prx, ptx = BW.last.get(pid, (rx, tx))
        r = rates.setdefault(a, [0.0, 0.0])
        r[0] += max(0, rx - prx) / dt
        r[1] += max(0, tx - ptx) / dt
    BW.last = snap
    BW.rates, BW.totals = rates, tot
    if len(BW.names) > 4000:
        BW.names.clear()


def bw_payload():
    if not ADMIN:
        return {"available": False, "reason": "admin", "apps": []}
    if not BW.started:
        return {"available": False, "reason": BW.error or "starting", "apps": []}
    apps = []
    for name, (rx, tx) in BW.totals.items():
        r = BW.rates.get(name, [0.0, 0.0])
        apps.append({"name": name, "down": round(r[0]), "up": round(r[1]), "rx": rx, "tx": tx})
    return {"available": True, "reason": "", "apps": apps}


def net_payload():
    rate = list(Net.rate)
    io = psutil.net_io_counters()
    conns = net_connections()
    return {"conns": conns, "rate": [[round(t), d, u] for t, d, u in rate], "total_down": io.bytes_recv, "total_up": io.bytes_sent,
            "devices": net_devices(), "scanning": Net.scanning, "scan_finished": Net.scan_finished,
            "subnet": Net.subnet, "my_ip": Net.my_ip, "admin": ADMIN, "bw": bw_payload(),
            "netrules": [dict(r, status=NET_STATUS.get(r["id"], "")) for r in CFG.get("netrules", [])]}


# ---- network limits: upload throttle (Windows QoS policy) and internet block (Windows Firewall rule). Need admin.
NETMODES = {"throttle", "block"}
NET_STATUS = {}       # rule id -> "" (ok) or an error message
SAFE_EXE = re.compile(r"^[A-Za-z0-9._\- ()]{1,80}$")


def _ps(script, timeout=40):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                       capture_output=True, text=True, timeout=timeout, creationflags=NOWIN)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip().splitlines()[0] if (r.stderr or r.stdout).strip() else "PowerShell failed")
    return r.stdout


def _psq(s):
    return "'" + str(s).replace("'", "''") + "'"


def exe_paths(name):
    out = set()
    for p in psutil.process_iter(["name", "exe"]):
        if (p.info["name"] or "").lower() == name.lower() and p.info.get("exe"):
            out.add(p.info["exe"])
    return sorted(out)


def net_rule_remove(rule):
    n = _psq("RamCapper-" + rule["id"])
    _ps(f"Get-NetQosPolicy -PolicyStore ActiveStore -Name {n} -ErrorAction SilentlyContinue | Remove-NetQosPolicy -PolicyStore ActiveStore -Confirm:$false; "
        f"Get-NetFirewallRule -Name {n} -ErrorAction SilentlyContinue | Remove-NetFirewallRule")


def net_rule_apply(rule):
    """(Re)create the Windows policy for one rule. Raises RuntimeError with a readable message on failure."""
    if not ADMIN:
        raise RuntimeError("Administrator rights are required - use 'Restart as administrator'")
    if not SAFE_EXE.match(rule["name"]):
        raise RuntimeError("Unsupported app name")
    net_rule_remove(rule)
    n = _psq("RamCapper-" + rule["id"])
    if rule["mode"] == "throttle":
        bps = int(rule["kbps"]) * 1000
        _ps(f"New-NetQosPolicy -Name {n} -AppPathNameMatchCondition {_psq(rule['name'])} -ThrottleRateActionBitsPerSecond {bps} -PolicyStore ActiveStore | Out-Null")
    else:
        paths = exe_paths(rule["name"]) or ([rule["path"]] if rule.get("path") else [])
        if not paths:
            raise RuntimeError("Start the app once so RamCapper can find its program file")
        rule["path"] = paths[0]
        for i, p in enumerate(paths):
            _ps(f"New-NetFirewallRule -Name {_psq('RamCapper-' + rule['id'] + ('' if i == 0 else '-' + str(i)))} "
                f"-DisplayName {_psq('RamCapper block ' + rule['name'])} -Program {_psq(p)} -Direction Outbound -Action Block | Out-Null")


def clean_netrule(r):
    name = str(r.get("name", "")).strip().lower()
    mode = r.get("mode")
    if not name or mode not in NETMODES or not SAFE_EXE.match(name):
        raise ValueError("Choose an app and a mode")
    out = {"id": str(r.get("id") or uuid.uuid4().hex[:8]), "name": name, "mode": mode, "enabled": bool(r.get("enabled", True)),
           "kbps": max(8, min(int(r.get("kbps", 1000)), 10_000_000)), "path": str(r.get("path", ""))}
    return out


def reapply_net_rules():
    """QoS policies live in the ActiveStore and vanish at reboot; put enabled ones back when RamCapper starts."""
    for r in list(CFG.get("netrules", [])):
        if r["enabled"] and r["mode"] == "throttle":
            try:
                net_rule_apply(r)
                NET_STATUS[r["id"]] = ""
            except Exception as e:
                NET_STATUS[r["id"]] = str(e)


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
        tray_remove()
        bw_stop()
        release_caps()
        with wlock:
            wdb.commit()
            wdb.close()
    finally:
        os._exit(0)


# ---------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    server_version = "RamCapper/" + VERSION

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
            fname = "index.html" if u.path == "/" else u.path[1:]
            if re.fullmatch(r"[a-z0-9_]+\.(html|css|js|png)", fname):          # the dashboard: one page per tab + shared css/js
                fp = os.path.join(HERE, "web", fname)
                if os.path.isfile(fp):
                    with open(fp, "rb") as f:
                        return self._send(200, f.read(), STATIC_TYPES[fname.rsplit(".", 1)[1]])
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
                if q.get("ui"):
                    UI_SEEN[0] = time.time()
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
                                        "db_size": size, "frozen": FROZEN, "port": PORT, "version": VERSION, "minibar": pill_mode()})
            if u.path == "/api/shortcuts":
                return self._send(200, shortcut_state())
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
                    new["netrules"] = CFG.get("netrules", [])
                    new["minibar"] = CFG.get("minibar", "minimized")
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
                        bw_stop()
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
                    Net.force_ident = True      # a manual scan re-identifies every device
                    threading.Thread(target=net_scan, daemon=True).start()
                return self._send(200, {})
            if path == "/api/minibar":
                if body.get("preview"):
                    PILL["preview"] = time.time() + 6
                if body.get("mode") in PILL_MODES:
                    with cfg_lock:
                        CFG["minibar"] = body["mode"]
                        save_cfg()
                return self._send(200, {"minibar": pill_mode()})
            if path == "/api/shortcut":
                where = body.get("where")
                if where not in ("start", "desktop"):
                    return self._send(400, {"error": "bad target"})
                if body.get("reveal"):
                    lnk = shortcut_path(where)
                    if os.path.exists(lnk):
                        subprocess.Popen(["explorer", f"/select,{lnk}"])
                    return self._send(200, shortcut_state())
                try:
                    set_shortcut(where, bool(body.get("enabled")))
                except Exception as e:
                    return self._send(400, {"error": f"Could not change the shortcut: {e}"})
                return self._send(200, shortcut_state())
            if path == "/api/show":          # a second launch / the tray asks for the window
                show_window()
                return self._send(200, {})
            if path == "/api/closing":       # the window is about to close: tell the user the app is still running
                UI_SEEN[0] = 0.0
                tray_balloon("RamCapper is still running", "Monitoring and limits stay active. Click the tray icon to reopen, or right-click to quit.")
                closed = bool(find_ui_windows())
                if closed:
                    threading.Timer(0.25, close_ui_window).start()   # after this response has been delivered
                return self._send(200, {"closed": closed})
            if path == "/api/netrule":
                if not module_on("network"):
                    return self._send(409, {"error": "network module is off"})
                act = body.get("action")
                with cfg_lock:
                    rules = CFG.setdefault("netrules", [])
                    try:
                        if act == "add":
                            r = clean_netrule(body.get("rule", {}))
                            for old in [x for x in rules if x["name"] == r["name"] and x["mode"] == r["mode"]]:
                                if ADMIN:
                                    net_rule_remove(old)
                                rules.remove(old)
                            net_rule_apply(r)
                            NET_STATUS[r["id"]] = ""
                            rules.append(r)
                        else:
                            r = next((x for x in rules if x["id"] == body.get("id")), None)
                            if r is None:
                                return self._send(404, {"error": "rule not found"})
                            if act == "toggle":
                                on = bool(body.get("enabled"))
                                if on:
                                    net_rule_apply(r)
                                elif ADMIN:
                                    net_rule_remove(r)
                                else:
                                    raise RuntimeError("Administrator rights are required to change this limit")
                                r["enabled"] = on
                            elif act == "delete":
                                if ADMIN:
                                    net_rule_remove(r)
                                rules.remove(r)
                        save_cfg()
                    except (RuntimeError, ValueError, subprocess.SubprocessError) as e:
                        return self._send(400, {"error": str(e)})
                return self._send(200, {"netrules": rules})
            if path == "/api/net/label":
                mac = str(body.get("mac", "")).lower()
                if not re.fullmatch(r"[0-9a-f]{2}(-[0-9a-f]{2}){5}", mac):
                    return self._send(400, {"error": "bad MAC"})
                with wlock:
                    wdb.execute("UPDATE devices SET label=? WHERE mac=?", (str(body.get("label", "")).strip()[:60], mac))
                    wdb.commit()
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


def shortcut_path(where):
    if where == "start":
        base = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs")
    else:
        base = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
        if not os.path.isdir(base):
            base = os.path.join(os.environ.get("USERPROFILE", ""), "OneDrive", "Desktop")
    return os.path.join(base, "RamCapper.lnk")


def shortcut_state():
    return {"start": os.path.exists(shortcut_path("start")), "desktop": os.path.exists(shortcut_path("desktop")),
            "frozen": FROZEN, "start_dir": os.path.dirname(shortcut_path("start"))}


def set_shortcut(where, on):
    path = shortcut_path(where)
    if not on:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        return
    if FROZEN:
        target, args, icon = sys.executable, "", sys.executable
    else:
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        target = pyw if os.path.exists(pyw) else sys.executable
        args = '"' + os.path.abspath(__file__) + '"'
        icon = os.path.join(HERE, "assets", "ramcapper.ico")
    script = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut(%s);$s.TargetPath=%s;$s.Arguments=%s;$s.WorkingDirectory=%s;"
              "$s.IconLocation=%s;$s.Description='RamCapper - RAM monitor and limiter';$s.Save()"
              % (_psq(path), _psq(target), _psq(args), _psq(APP_DIR), _psq(icon)))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _ps(script)


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


STATIC_TYPES = {"html": "text/html; charset=utf-8", "css": "text/css; charset=utf-8",
                "js": "application/javascript; charset=utf-8", "png": "image/png"}
UI_SEEN = [0.0]     # last time a dashboard window polled us (it does so every 2 s while open)


def find_ui_windows():
    """Handles of open RamCapper app windows (title "... · RamCapper"; a normal browser tab has a " - Edge" suffix)."""
    found = []
    PROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsIconic.argtypes = [wintypes.HWND]
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.EnumWindows.argtypes = [PROC, wintypes.LPARAM]

    def cb(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            if 0 < n < 200:
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                cls = ctypes.create_unicode_buffer(64)
                user32.GetClassNameW(hwnd, cls, 64)
                t = buf.value
                if cls.value == "Chrome_WidgetWin_1" and (t == "RamCapper" or t.endswith("· RamCapper")):
                    found.append(hwnd)
        return True

    user32.EnumWindows(PROC(cb), 0)
    return found


def close_ui_window():
    """Close the dashboard window (the app keeps running). True if a window was found."""
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    found = find_ui_windows()
    for h in found:
        user32.PostMessageW(h, 0x0010, 0, 0)       # WM_CLOSE
    UI_SEEN[0] = 0.0
    return bool(found)


def focus_ui_window():
    """Bring an already-open dashboard window to the front. True if one was found."""
    found = find_ui_windows()
    if not found:
        return False
    hwnd = found[0]
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)                 # SW_RESTORE
    user32.keybd_event(0x12, 0, 0, 0)              # tapping Alt lets SetForegroundWindow through
    user32.keybd_event(0x12, 0, 2, 0)
    user32.SetForegroundWindow(hwnd)
    return True


SHOW_LOCK = threading.Lock()
LAST_OPEN = [0.0]


def show_window():
    """Open the dashboard, or focus it if it is already open (never a second window)."""
    with SHOW_LOCK:
        if focus_ui_window():
            return
        if time.time() - LAST_OPEN[0] < 8:         # a window was launched a moment ago and is still loading
            return
        LAST_OPEN[0] = time.time()
        open_window()


def ask_running_to_show():
    """Another copy is already running: ask it to show/focus its window."""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/show", data=b"{}", method="POST", headers={"X-RamCapper": "1"})
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        open_window()


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


# ---------------------------------------------------------------- tray icon (notification area)
LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
WM_TRAY, WM_COMMAND, WM_DESTROY = 0x0401, 0x0111, 0x0002
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 1, 2, 4, 0x10
TRAY = {}


class NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT), ("uFlags", wintypes.UINT),
                ("uCallbackMessage", wintypes.UINT), ("hIcon", VP), ("szTip", wintypes.WCHAR * 128),
                ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD), ("szInfo", wintypes.WCHAR * 256),
                ("uTimeout", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", ctypes.c_byte * 16), ("hBalloonIcon", VP)]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                ("hInstance", VP), ("hIcon", VP), ("hCursor", VP), ("hbrBackground", VP), ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR)]


def _tray_icon_handle():
    small = VP()
    if FROZEN and shell32.ExtractIconExW(sys.executable, 0, None, ctypes.byref(small), 1) > 0 and small:
        return small
    ico = os.path.join(HERE, "assets", "ramcapper.ico")
    h = user32.LoadImageW(None, ico, 1, 16, 16, 0x10) if os.path.exists(ico) else None
    return h or user32.LoadIconW(None, ctypes.c_void_p(32512))


def tray_balloon(title, msg):
    nid = TRAY.get("nid")
    if nid is None:
        return
    nid.uFlags = NIF_INFO
    nid.szInfoTitle, nid.szInfo, nid.dwInfoFlags = title[:63], msg[:255], 1
    shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))


def tray_remove():
    nid = TRAY.get("nid")
    if nid is not None:
        shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))


def _tray_thread(first_balloon):
    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = LRESULT
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int,
                                       ctypes.c_int, ctypes.c_int, wintypes.HWND, VP, VP, VP]
    user32.LoadImageW.restype = VP
    user32.LoadImageW.argtypes = [VP, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user32.LoadIconW.restype = VP
    user32.LoadIconW.argtypes = [VP, VP]
    user32.CreatePopupMenu.restype = VP
    user32.AppendMenuW.argtypes = [VP, wintypes.UINT, VP, wintypes.LPCWSTR]
    user32.TrackPopupMenu.argtypes = [VP, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, VP]
    user32.DestroyMenu.argtypes = [VP]
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, VP]
    taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")

    def wndproc(hwnd, msg, wparam, lparam):
        if msg == WM_TRAY:
            ev = lparam & 0xFFFF
            if ev == 0x0202:                                 # left click -> open (or focus) the dashboard
                threading.Thread(target=show_window, daemon=True).start()
            elif ev in (0x0205, 0x007B):                     # right click -> menu
                pt = wintypes.POINT()
                user32.GetCursorPos(ctypes.byref(pt))
                menu = user32.CreatePopupMenu()
                user32.AppendMenuW(menu, 0, 1, "Open RamCapper")
                user32.AppendMenuW(menu, 0x800, 0, None)    # separator
                user32.AppendMenuW(menu, 0, 2, "Quit RamCapper")
                user32.SetForegroundWindow(hwnd)
                user32.TrackPopupMenu(menu, 0x0002, pt.x, pt.y, 0, hwnd, None)   # TPM_RIGHTBUTTON; the choice arrives as WM_COMMAND
                user32.PostMessageW(hwnd, 0, 0, 0)
                user32.DestroyMenu(menu)
            return 0
        if msg == WM_COMMAND:
            cmd = wparam & 0xFFFF
            if cmd == 1:
                show_window()
            elif cmd == 2:
                threading.Thread(target=quit_app, daemon=True).start()
            return 0
        if msg == taskbar_created:                           # Explorer restarted: put the icon back
            shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(TRAY["nid"]))
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    TRAY["proc"] = WNDPROC(wndproc)                          # keep a reference or it gets garbage-collected
    wc = WNDCLASSW()
    wc.lpfnWndProc, wc.lpszClassName = TRAY["proc"], "RamCapperTray"
    wc.hInstance = k32.GetModuleHandleW(None)
    user32.RegisterClassW(ctypes.byref(wc))
    hwnd = user32.CreateWindowExW(0, "RamCapperTray", "RamCapper", 0, 0, 0, 0, 0, None, None, wc.hInstance, None)
    nid = NOTIFYICONDATAW()
    nid.cbSize, nid.hWnd, nid.uID = ctypes.sizeof(nid), hwnd, 1
    nid.uFlags, nid.uCallbackMessage, nid.hIcon = NIF_MESSAGE | NIF_ICON | NIF_TIP, WM_TRAY, _tray_icon_handle()
    nid.szTip = "RamCapper " + VERSION + " - running (click to open)"
    TRAY["nid"] = nid
    if not shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)):
        print("tray icon could not be added", file=sys.stderr)
    if first_balloon:
        tray_balloon("RamCapper is running", "It keeps working in the background. Use this tray icon to open it or quit.")
    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


def start_tray(first_balloon):
    k32.GetModuleHandleW.restype = VP
    k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    threading.Thread(target=_tray_thread, args=(first_balloon,), daemon=True).start()


# ---------------------------------------------------------------- mini stats bar
# A "notch" that hangs from the top edge of the screen (top-centre) with one line of live stats. By default it slides down while
# the dashboard window is minimized. Click it to bring the dashboard back; right-click for a menu.
# Drawn with GDI+ into a per-pixel-alpha layered window, so every curve is anti-aliased.
PILL_MODES = ("off", "minimized", "hidden", "always")
PILL = {"hwnd": None, "flash": ("", 0.0), "preview": 0.0, "hist": deque(maxlen=60), "tick": 0, "shown": False, "anim": None,
        "frame": None}
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
MB_ = 1048576
GB_ = 1073741824


def pill_mode():
    m = CFG.get("minibar", "minimized")
    return m if m in PILL_MODES else "minimized"


def pill_flash(text):
    """Show a short message in the notch for a few seconds (limiter actions)."""
    PILL["flash"] = (text[:64], time.time() + 6)


def _argb(r, g, b, a=255):
    return (a << 24) | (r << 16) | (g << 8) | b


PILL_COL = {"bg": _argb(9, 11, 16), "text": _argb(232, 238, 246), "muted": _argb(135, 148, 167), "ok": _argb(52, 195, 143),
            "warn": _argb(242, 180, 65), "bad": _argb(239, 106, 100), "accent": _argb(110, 160, 255), "line": _argb(60, 72, 92)}


def _pill_fmt_rate(b):
    return f"{b / MB_:.1f} MB/s" if b >= MB_ * 0.95 else (f"{b / 1024:.0f} KB/s" if b >= 1024 else f"{b:.0f} B/s")


def _pill_app_color(name):
    import colorsys
    r, g, b = colorsys.hsv_to_rgb((sum(ord(c) * (i + 3) for i, c in enumerate(name)) % 360) / 360, 0.55, 0.95)
    return _argb(int(r * 255), int(g * 255), int(b * 255))


def _pill_items():
    """The content of the notch as a list of items, or None while there is no data yet."""
    with ST.lock:
        s = dict(ST.sysinfo)
        apps = list(ST.apps.values())
    if not s:
        return None
    pct = s["percent"]
    with cfg_lock:
        g = dict(CFG.get("global", {}))
    limit = g.get("threshold", 90) if g.get("enabled") else 90
    level = "bad" if pct >= limit else ("warn" if pct >= 70 else "ok")
    cpu = psutil.cpu_percent(None)
    items = [("dot", PILL_COL[level]), ("text", f"{pct:.0f}%", "text", True),
             ("text", f"{s['used'] / GB_:.1f} / {s['total'] / GB_:.1f} GB", "muted", False),
             ("spark", PILL_COL[level]), ("sep",), ("text", "CPU ", "muted", False), ("text", f"{cpu:.0f}%", "text", True)]
    if module_on("network") and Net.rate:
        _, d, u = Net.rate[-1]
        items += [("sep",), ("text", "↓ ", "accent", True), ("text", _pill_fmt_rate(d), "text", False),
                  ("text", "  ↑ ", "warn", True), ("text", _pill_fmt_rate(u), "text", False)]
    items.append(("sep",))
    txt, until = PILL["flash"]
    if txt and time.time() < until:
        items.append(("text", "⚡ " + txt, "accent", True))
    elif apps:
        top = max(apps, key=lambda a: a["rss"])
        items += [("dot", _pill_app_color(top["name"])), ("text", top["name"], "text", False),
                  ("text", f"  {top['rss'] / GB_:.1f} GB" if top["rss"] >= GB_ else f"  {top['rss'] / MB_:.0f} MB", "muted", False)]
    return items, level, pct >= limit


class _GpRectF(ctypes.Structure):
    _fields_ = [("x", ctypes.c_float), ("y", ctypes.c_float), ("w", ctypes.c_float), ("h", ctypes.c_float)]


class _GpPointF(ctypes.Structure):
    _fields_ = [("x", ctypes.c_float), ("y", ctypes.c_float)]


class _BMIH(ctypes.Structure):
    _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG), ("biPlanes", wintypes.WORD),
                ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD), ("biSizeImage", wintypes.DWORD),
                ("biXPelsPerMeter", wintypes.LONG), ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD),
                ("biClrImportant", wintypes.DWORD)]


class _BLEND(ctypes.Structure):
    _fields_ = [("op", ctypes.c_ubyte), ("flags", ctypes.c_ubyte), ("alpha", ctypes.c_ubyte), ("fmt", ctypes.c_ubyte)]


def _pill_thread():
    PV, I, F, U = ctypes.c_void_p, ctypes.c_int, ctypes.c_float, ctypes.c_uint32
    PP = ctypes.POINTER
    gp = ctypes.WinDLL("gdiplus")
    for n, args in {
        "GdipCreateFromHDC": [PV, PP(PV)], "GdipGetImageGraphicsContext": [PV, PP(PV)],
        "GdipCreateBitmapFromScan0": [I, I, I, I, PV, PP(PV)], "GdipDisposeImage": [PV], "GdipDeleteGraphics": [PV],
        "GdipSetSmoothingMode": [PV, I], "GdipSetTextRenderingHint": [PV, I], "GdipSetPixelOffsetMode": [PV, I],
        "GdipGraphicsClear": [PV, U], "GdipCreatePath": [I, PP(PV)], "GdipDeletePath": [PV],
        "GdipAddPathArc": [PV, F, F, F, F, F, F], "GdipAddPathLine": [PV, F, F, F, F],
        "GdipCreateSolidFill": [U, PP(PV)], "GdipDeleteBrush": [PV], "GdipCreatePen1": [U, F, I, PP(PV)], "GdipDeletePen": [PV],
        "GdipSetPenLineCap197819": [PV, I, I, I], "GdipSetPenLineJoin": [PV, I], "GdipSetCompositingQuality": [PV, I],
        "GdipFillPath": [PV, PV, PV], "GdipDrawPath": [PV, PV, PV], "GdipFillEllipse": [PV, PV, F, F, F, F],
        "GdipDrawLine": [PV, PV, F, F, F, F], "GdipDrawCurve": [PV, PV, PV, I],
        "GdipCreateFontFamilyFromName": [wintypes.LPCWSTR, PV, PP(PV)], "GdipCreateFont": [PV, F, I, I, PP(PV)],
        "GdipStringFormatGetGenericTypographic": [PP(PV)], "GdipCloneStringFormat": [PV, PP(PV)],
        "GdipSetStringFormatFlags": [PV, I], "GdipSetStringFormatLineAlign": [PV, I],
        "GdipMeasureString": [PV, wintypes.LPCWSTR, I, PV, PV, PV, PV, PV, PV],
        "GdipDrawString": [PV, wintypes.LPCWSTR, I, PV, PV, PV, PV],
    }.items():
        f = getattr(gp, n)
        f.argtypes, f.restype = args, I
    tok = ctypes.c_size_t(0)
    si = (ctypes.c_uint32 * 8)(1, 0, 0, 0, 0, 0, 0, 0)
    gp.GdiplusStartup.argtypes = [PP(ctypes.c_size_t), PV, PV]
    gp.GdiplusStartup(ctypes.byref(tok), si, None)

    for n, res, args in [
        ("CreateCompatibleDC", PV, [PV]), ("SelectObject", PV, [PV, PV]), ("DeleteObject", wintypes.BOOL, [PV]),
        ("CreateDIBSection", PV, [PV, PV, wintypes.UINT, PP(PV), PV, wintypes.DWORD]),
    ]:
        f = getattr(gdi32, n)
        f.restype, f.argtypes = res, args
    for n, res, args in [
        ("GetDC", PV, [PV]), ("ReleaseDC", I, [PV, PV]), ("ShowWindow", wintypes.BOOL, [wintypes.HWND, I]),
        ("SetWindowPos", wintypes.BOOL, [wintypes.HWND, PV, I, I, I, I, wintypes.UINT]),
        ("UpdateLayeredWindow", wintypes.BOOL, [wintypes.HWND, PV, PP(wintypes.POINT), PP(wintypes.SIZE), PV, PP(wintypes.POINT),
                                                wintypes.COLORREF, PP(_BLEND), wintypes.DWORD]),
        ("SetTimer", PV, [wintypes.HWND, PV, wintypes.UINT, PV]), ("KillTimer", wintypes.BOOL, [wintypes.HWND, PV]),
        ("IsIconic", wintypes.BOOL, [wintypes.HWND]), ("SetForegroundWindow", wintypes.BOOL, [wintypes.HWND]),
        ("DefWindowProcW", LRESULT, [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]),
        ("CreateWindowExW", wintypes.HWND, [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, I, I, I, I, wintypes.HWND, PV, PV, PV]),
        ("CreatePopupMenu", PV, []), ("AppendMenuW", wintypes.BOOL, [PV, wintypes.UINT, PV, wintypes.LPCWSTR]),
        ("TrackPopupMenu", wintypes.BOOL, [PV, wintypes.UINT, I, I, I, wintypes.HWND, PV]), ("DestroyMenu", wintypes.BOOL, [PV]),
        ("PostMessageW", wintypes.BOOL, [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]),
    ]:
        f = getattr(user32, n)
        f.restype, f.argtypes = res, args
    try:
        scale = user32.GetDpiForSystem() / 96.0
    except Exception:
        scale = 1.0
    S_ = lambda v: int(round(v * scale))

    scr = user32.GetDC(None)
    mdc = gdi32.CreateCompatibleDC(scr)
    scratch = PV()
    gp.GdipCreateFromHDC(scr, ctypes.byref(scratch))           # only used to measure text
    fam = PV()
    gp.GdipCreateFontFamilyFromName("Segoe UI", None, ctypes.byref(fam))
    if not fam:
        gp.GdipCreateFontFamilyFromName("Arial", None, ctypes.byref(fam))
    fonts = {}
    for key, style in (("reg", 0), ("bold", 1)):
        fp = PV()
        gp.GdipCreateFont(fam, F(13.0 * scale), style, 2, ctypes.byref(fp))
        fonts[key] = fp
    fmt = PV()
    gp.GdipStringFormatGetGenericTypographic(ctypes.byref(fmt))
    fmt2 = PV()
    gp.GdipCloneStringFormat(fmt, ctypes.byref(fmt2))
    gp.GdipSetStringFormatFlags(fmt2, 0x1000 | 0x0800)          # no wrap, measure trailing spaces
    gp.GdipSetStringFormatLineAlign(fmt2, 1)                    # centre vertically in the layout box

    def measure(text, bold):
        r_in, r_out = _GpRectF(0, 0, 4000, 100), _GpRectF()
        gp.GdipMeasureString(scratch, text, len(text), fonts["bold" if bold else "reg"], ctypes.byref(r_in), fmt2, ctypes.byref(r_out), None, None)
        return int(r_out.w + 0.999)

    def brush(col):
        b = PV()
        gp.GdipCreateSolidFill(col, ctypes.byref(b))
        return b

    def pen(col, w):
        p = PV()
        gp.GdipCreatePen1(col, F(w), 2, ctypes.byref(p))
        gp.GdipSetPenLineCap197819(p, 2, 2, 0)                    # round caps
        gp.GdipSetPenLineJoin(p, 2)
        return p

    st = {"dib": None, "bmp": None, "g": None, "W": 0, "H": 0}

    def free_frame():
        if st["g"]:
            gp.GdipDeleteGraphics(st["g"])
        if st["bmp"]:
            gp.GdipDisposeImage(st["bmp"])
        st["g"] = st["bmp"] = None

    def render():
        got = _pill_items()
        if not got:
            return False
        items, level, alarm = got
        H, m, r = S_(36), S_(2), S_(16)                             # height, margin for the rim, bottom corner radius
        e = m
        padx, gap, sep = S_(16), S_(9), S_(13)
        widths = [S_(9) if it[0] == "dot" else S_(60) if it[0] == "spark" else sep if it[0] == "sep" else measure(it[1], it[3]) for it in items]
        W = max(S_(140), 2 * e + 2 * padx + sum(widths) + gap * (len(items) - 1))
        bi = _BMIH(ctypes.sizeof(_BMIH), W, -H, 1, 32, 0, 0, 0, 0, 0, 0)
        bits = PV()
        dib = gdi32.CreateDIBSection(mdc, ctypes.byref(bi), 0, ctypes.byref(bits), None, 0)
        if not dib:
            return False
        gdi32.SelectObject(mdc, dib)
        free_frame()
        if st["dib"]:
            gdi32.DeleteObject(st["dib"])
        st["dib"], st["W"], st["H"] = dib, W, H
        bmp = PV()
        gp.GdipCreateBitmapFromScan0(W, H, W * 4, 0x000E200B, bits, ctypes.byref(bmp))     # 32bppPARGB over the DIB memory
        g = PV()
        gp.GdipGetImageGraphicsContext(bmp, ctypes.byref(g))
        st["bmp"], st["g"] = bmp, g
        gp.GdipSetSmoothingMode(g, 5)                                # anti-alias, 8x8 sub-pixel sampling
        gp.GdipSetCompositingQuality(g, 2)
        gp.GdipSetTextRenderingHint(g, 3)                            # anti-aliased, grid-fitted (crisp) text
        gp.GdipSetPixelOffsetMode(g, 2)
        gp.GdipGraphicsClear(g, 0)
        # the notch: straight sides coming down from the top edge, rounded bottom corners. The outline is inset by half the
        # rim width so the rim is fully inside the bitmap (a stroke centred on the edge would be half clipped and look soft).
        rim = max(1.0, round(1.5 * scale))
        o = rim / 2.0 + m / 2.0
        path = PV()
        gp.GdipCreatePath(0, ctypes.byref(path))
        gp.GdipAddPathLine(path, F(o), F(-6), F(o), F(H - o - r))                                  # left side (starts above the screen edge)
        gp.GdipAddPathArc(path, F(o), F(H - o - 2 * r), F(2 * r), F(2 * r), F(180), F(-90))        # bottom left
        gp.GdipAddPathLine(path, F(o + r), F(H - o), F(W - o - r), F(H - o))
        gp.GdipAddPathArc(path, F(W - o - 2 * r), F(H - o - 2 * r), F(2 * r), F(2 * r), F(90), F(-90))   # bottom right
        gp.GdipAddPathLine(path, F(W - o), F(H - o - r), F(W - o), F(-6))                         # right side
        fillb = brush(PILL_COL["bg"])
        gp.GdipFillPath(g, fillb, path)
        gp.GdipDeleteBrush(fillb)
        col = PILL_COL[level]
        glow = (col & 0x00FFFFFF) | ((255 if alarm and int(time.time() * 1.6) % 2 else 215) << 24)
        po = pen(glow, rim)
        gp.GdipDrawPath(g, po, path)                                 # coloured rim (not along the top edge)
        gp.GdipDeletePen(po)
        gp.GdipDeletePath(path)
        x = e + padx
        hist = list(PILL["hist"])
        for it, w in zip(items, widths):
            k = it[0]
            if k == "dot":
                b = brush(it[1])
                gp.GdipFillEllipse(g, b, F(x), F((H - w) / 2), F(w), F(w))
                gp.GdipDeleteBrush(b)
            elif k == "spark" and len(hist) >= 3:
                lo, hi = min(hist), max(hist)
                hi = max(hi, lo + 4)
                sh = S_(15)
                pts = (_GpPointF * len(hist))(*[_GpPointF(x + i * (w - 1) / (len(hist) - 1), (H + sh) / 2 - (v - lo) / (hi - lo) * sh) for i, v in enumerate(hist)])
                p = pen(it[1], 1.7 * scale)
                gp.GdipDrawCurve(g, p, pts, len(hist))
                gp.GdipDeletePen(p)
                b = brush(it[1])
                gp.GdipFillEllipse(g, b, F(pts[-1].x - S_(2)), F(pts[-1].y - S_(2)), F(S_(4)), F(S_(4)))
                gp.GdipDeleteBrush(b)
            elif k == "sep":
                p = pen(PILL_COL["line"], 1.0 * scale)
                gp.GdipDrawLine(g, p, F(x + w / 2), F(S_(10)), F(x + w / 2), F(H - S_(10)))
                gp.GdipDeletePen(p)
            elif k == "text":
                b = brush(PILL_COL[it[2]])
                rc = _GpRectF(x, 0, w + S_(6), H)
                gp.GdipDrawString(g, it[1], len(it[1]), fonts["bold" if it[3] else "reg"], ctypes.byref(rc), fmt2, b)
                gp.GdipDeleteBrush(b)
            x += w + gap
        return True

    def present(hwnd, y):
        W, H = st["W"], st["H"]
        sw = ctypes.windll.user32.GetSystemMetrics(0)
        dst = wintypes.POINT((sw - W) // 2, y)
        size = wintypes.SIZE(W, H)
        src = wintypes.POINT(0, 0)
        bl = _BLEND(0, 0, 255, 1)                                    # AC_SRC_OVER, AC_SRC_ALPHA
        user32.UpdateLayeredWindow(hwnd, scr, ctypes.byref(dst), ctypes.byref(size), mdc, ctypes.byref(src), 0, ctypes.byref(bl), 2)

    def anim_y():
        a = PILL["anim"]
        if not a:
            return 0, False
        t = min(1.0, (time.time() - a["t0"]) / 0.30)
        p = 1 - (1 - t) ** 3 if a["dir"] > 0 else (1 - t) ** 3     # slide down (ease-out) / slide up (ease-in)
        return int(-st["H"] * (1 - p)), t >= 1.0

    def want_visible():
        if time.time() < PILL["preview"]:
            return True
        mode = pill_mode()
        if mode == "off":
            return False
        if mode == "always":
            return True
        wins = find_ui_windows()
        if mode == "minimized":
            return bool(wins) and all(user32.IsIconic(h) for h in wins)
        return not any(not user32.IsIconic(h) for h in wins)

    def on_anim(hwnd):
        y, done = anim_y()
        present(hwnd, y)
        if done:
            user32.KillTimer(hwnd, PV(2))
            a = PILL["anim"]
            PILL["anim"] = None
            if a and a["dir"] < 0:
                PILL["shown"] = False
                user32.ShowWindow(hwnd, 0)

    def start_anim(hwnd, direction):
        PILL["anim"] = {"dir": direction, "t0": time.time()}
        user32.SetTimer(hwnd, PV(2), 15, None)

    def on_tick(hwnd):
        PILL["tick"] += 1
        if PILL["tick"] % 2 == 0:                                    # one history sample per second
            with ST.lock:
                p = ST.sysinfo.get("percent")
            if p is not None:
                PILL["hist"].append(p)
        try:
            want = want_visible()
            hiding = bool(PILL["anim"]) and PILL["anim"]["dir"] < 0
            if want and (not PILL["shown"] or hiding):
                if render():
                    if not PILL["shown"]:
                        user32.ShowWindow(hwnd, 4)                   # SW_SHOWNOACTIVATE
                    user32.SetWindowPos(hwnd, PV(-1), 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0010)   # topmost, no move/size/activate
                    PILL["shown"] = True
                    start_anim(hwnd, 1)
            elif want and PILL["shown"]:
                if render():
                    present(hwnd, 0 if not PILL["anim"] else anim_y()[0])
            elif not want and PILL["shown"] and not hiding:
                start_anim(hwnd, -1)
        except Exception as ex:
            print("minibar error:", ex, file=sys.stderr)

    def wndproc(hwnd, msg, wparam, lparam):
        if msg == 0x0113:                                            # WM_TIMER
            if wparam == 2:
                on_anim(hwnd)
            else:
                on_tick(hwnd)
            return 0
        if msg == 0x0021:                                            # WM_MOUSEACTIVATE -> never take focus
            return 3
        if msg == 0x0202:                                            # click: bring the dashboard back
            PILL["preview"] = 0.0
            threading.Thread(target=show_window, daemon=True).start()
            return 0
        if msg == 0x0205:                                            # right click: menu
            pt = wintypes.POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            menu = user32.CreatePopupMenu()
            user32.AppendMenuW(menu, 0, 1, "Open RamCapper")
            user32.AppendMenuW(menu, 0, 2, "Optimize now")
            user32.AppendMenuW(menu, 0, 3, "Turn off notch")
            user32.AppendMenuW(menu, 0x800, 0, None)
            user32.AppendMenuW(menu, 0, 4, "Quit RamCapper")
            user32.SetForegroundWindow(hwnd)
            user32.TrackPopupMenu(menu, 0x0002, pt.x, pt.y, 0, hwnd, None)
            user32.PostMessageW(hwnd, 0, 0, 0)
            user32.DestroyMenu(menu)
            return 0
        if msg == 0x0111:                                            # WM_COMMAND
            cmd = wparam & 0xFFFF
            if cmd == 1:
                threading.Thread(target=show_window, daemon=True).start()
            elif cmd == 2:
                threading.Thread(target=lambda: trim_apps(None), daemon=True).start()
            elif cmd == 3:
                with cfg_lock:
                    CFG["minibar"] = "off"
                    save_cfg()
            elif cmd == 4:
                threading.Thread(target=quit_app, daemon=True).start()
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    PILL["proc"] = WNDPROC(wndproc)
    wc = WNDCLASSW()
    wc.lpfnWndProc, wc.lpszClassName = PILL["proc"], "RamCapperMiniBar"
    wc.hInstance = k32.GetModuleHandleW(None)
    wc.hCursor = user32.LoadCursorW(None, ctypes.c_void_p(32649))    # IDC_HAND
    user32.RegisterClassW(ctypes.byref(wc))
    # topmost tool window (no taskbar button), per-pixel-alpha layered, never activated
    hwnd = user32.CreateWindowExW(0x00000008 | 0x00000080 | 0x00080000 | 0x08000000, "RamCapperMiniBar", "RamCapper mini bar",
                                  0x80000000, 0, 0, 10, 10, None, None, wc.hInstance, None)
    PILL["hwnd"] = hwnd
    psutil.cpu_percent(None)
    user32.SetTimer(hwnd, PV(1), 500, None)
    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))


def start_minibar():
    k32.GetModuleHandleW.restype = VP
    k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    user32.LoadCursorW.restype = VP
    user32.LoadCursorW.argtypes = [VP, VP]
    user32.GetCursorPos.argtypes = [ctypes.POINTER(wintypes.POINT)]
    threading.Thread(target=_pill_thread, daemon=True).start()


def retire_other_version():
    """If the copy already running is another version (e.g. an old exe left running), ask it to quit.
    Returns True when a quit request was accepted. Same-version copies are left alone (single instance)."""
    if getattr(retire_other_version, "tried", False):
        return False
    retire_other_version.tried = True
    base = f"http://127.0.0.1:{PORT}"
    try:
        with urllib.request.urlopen(base + "/api/info", timeout=3) as r:
            info = json.loads(r.read().decode("utf-8", "replace"))
        if info.get("version") == VERSION:
            return False
        req = urllib.request.Request(base + "/api/quit", data=b"{}", method="POST", headers={"X-RamCapper": "1"})
        urllib.request.urlopen(req, timeout=3).read()
        return True
    except Exception:
        return False


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
            if not takeover and retire_other_version():
                deadline = time.time() + 10      # a different version was running: it is quitting, take its place
                continue
            if not no_open:
                ask_running_to_show()      # already running - just show/focus its window
            return
        time.sleep(0.4)
    SERVER["srv"] = srv
    atexit.register(release_caps)
    threading.Thread(target=sampler, daemon=True).start()
    if ADMIN:
        threading.Thread(target=reapply_net_rules, daemon=True).start()
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)         # crisp text in the mini bar on high-DPI screens
    except Exception:
        pass
    if "--no-tray" not in sys.argv:
        start_tray(first_balloon=not no_open and not takeover)
    start_minibar()
    if not no_open:
        threading.Timer(1.0, open_window).start()
    print(f"RamCapper running on http://127.0.0.1:{PORT}  (admin={ADMIN})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
