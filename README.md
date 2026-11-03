<p align="center">
  <img src="assets/icon.png" width="96" alt="RamCapper icon">
</p>

<h1 align="center">RamCapper</h1>

<p align="center">
  A lightweight Windows RAM monitor with per-app limits, plus network and disk-usage tools.<br>
  See <b>what</b> is eating your memory, <b>when</b> it happened, and cap it.
</p>

![RamCapper dashboard](docs/screenshot.png)

## Features

- **Live memory dashboard** – system gauge plus a stacked timeline of the top apps (5 min → 3 days). Hover for exact values at any moment; limiter actions are marked on the timeline.
- **Per-app view** – processes grouped by executable with icons, trend sparklines, 5-minute change and per-process drill-down.
- **Limiter** – set a limit per app (all its processes combined) with one of four actions:
  | Action | What it does |
  |---|---|
  | **Alert** | Logs an event and shows a toast. |
  | **Trim** | Returns the app's idle memory to Windows (safe, app keeps running). |
  | **Hard cap** | Windows enforces a working-set ceiling per process (limit ÷ process count). The app pages instead of growing; no crash. |
  | **Terminate** | Ends the app after it stays over its limit for N checks (2 s each). |
- **Emergency auto-trim** – trims every reachable process when system RAM crosses a threshold you choose.
- **Network tab** *(opt-in)* – live connections per app, throughput chart, and a scan of devices on your local subnet with new-device alerts.
- **Storage tab** *(opt-in)* – scan a drive or folder to see what takes the most space: drill-down folders, largest files, breakdown by file type. Read-only.
- **Portable** – single `.exe`, no installer. History and settings live in a folder you choose.
- **Safe by design** – clipboard owners are never trimmed, critical Windows processes can't be ended, and the web UI only listens on `127.0.0.1`.

## Quick start

### Download
Grab `RamCapper.exe` from the [Releases](../../releases) page and run it. A window opens; the app keeps running in the background until you press **Quit**.

> The executable is not code-signed, so Windows SmartScreen may warn on first run ("More info → Run anyway"). Some antivirus products flag PyInstaller binaries; building from source (below) avoids that.

### Run from source
Requires Windows 10/11 and Python 3.9+.

```bash
git clone https://github.com/tekno-lab/ramcapper.git
cd ramcapper
pip install -r requirements.txt
python ramcapper.py
```

## How to compile

The portable executable is built with [PyInstaller](https://pyinstaller.org). The dashboard (`index.html`) and icon are bundled into the single file.

**Prerequisites:** Windows 10/11 · Python 3.9+ on `PATH` · internet access for `pip`.

### One command

```bat
build.bat
```

This installs the dependencies and runs PyInstaller. The result is **`dist\RamCapper.exe`** (≈ 9 MB).

### Manual build

```bash
pip install -r requirements.txt pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --noconsole ^
    --icon assets\ramcapper.ico --name RamCapper ^
    --add-data "index.html;." ramcapper.py
```

Flag notes: `--onefile` produces the portable exe, `--noconsole` hides the console window, `--add-data "index.html;."` bundles the UI next to the code (Windows uses `;` as the separator).

### Troubleshooting the build

| Problem | Fix |
|---|---|
| `Unable to find ... index.html when adding binary and data files` | Run the command from the repository root (the folder containing `index.html`). |
| `ValueError: path is on mount 'D:', start on mount 'C:'` | Don't point `--workpath` / `--specpath` at a different drive than the project. The defaults are fine. |
| Antivirus quarantines `dist\RamCapper.exe` | Common false positive for PyInstaller one-file apps. Add an exclusion or run from source. |
| Replacing a running exe fails | Press **Quit** in RamCapper (or run `kill.bat`) first. |

### Regenerating the icon (optional)

The icon source is `assets/icon.svg`. To rebuild `assets/ramcapper.ico` and `assets/icon.png` (needs `pip install pillow` and Microsoft Edge):

```bash
python tools/make_icon.py
```

## Usage

| Command | Effect |
|---|---|
| `RamCapper.exe` | Start (or just show the window if already running). |
| `RamCapper.exe --admin` | Relaunch elevated (UAC prompt). Needed to trim, cap or end elevated/system processes. |
| `RamCapper.exe --data "E:\RamCapperData"` | Use a specific data folder. |
| `RamCapper.exe --no-open` | Run in the background without opening a window. |

You can also restart as administrator and move the data folder from the **Settings** tab.

`run.bat`, `run_admin.bat` and `kill.bat` are convenience launchers for the source version (`kill.bat` also stops the exe).

### Data location

`history.db` (3 days of memory history, events, known devices) and `config.json` (limits and switches) are stored, in order of priority:

1. `--data DIR`
2. `RAMCAPPER_DATA` environment variable
3. the folder saved from **Settings** (pointer in `datadir.txt` next to the exe, or `%APPDATA%\RamCapper`)
4. next to the program

`RAMCAPPER_PORT` changes the local port (default `8765`).

## How it works

- A sampler thread reads per-process memory with [psutil](https://github.com/giampaolo/psutil) every 2 s and stores the top apps in SQLite every 5 s.
- A tiny `http.server` on `127.0.0.1` serves the single-page dashboard and a JSON API. State-changing calls require a custom header and a matching `Host`, which blocks cross-site and DNS-rebinding requests.
- Trimming uses `EmptyWorkingSet`; hard caps use `SetProcessWorkingSetSizeEx` with the hard-max flag; both are skipped for clipboard-related processes.
- Memory shown is the **working set** (like Task Manager's "Memory" column, including shared pages), so a trim is visible immediately.

## Limitations

- Windows only.
- Per-process network bandwidth isn't available without ETW/driver support; throughput is whole-machine.
- Without administrator rights, protected and elevated processes can't be trimmed, capped or ended.
- Local-network discovery is a ping sweep of your own `/24` plus the ARP table, so devices that block ping and haven't talked to you recently may not appear.

## Project layout

```
ramcapper.py      backend: sampler, limiter, network/storage modules, HTTP server
index.html        dashboard (single file, no external dependencies)
assets/           icon source (SVG), .ico and .png
tools/            helper scripts (icon generation)
build.bat         one-command PyInstaller build
run*.bat kill.bat launchers for the source version
```

## License

RamCapper is **source-available, free for non-commercial use**, under the [PolyForm Noncommercial License 1.0.0](LICENSE).

You may use, modify and share it for personal use, learning, research, hobby projects, and non-profit/educational/government organizations. **Commercial use is not permitted** (including use inside a for-profit business, or bundling it into a paid product or service). For a commercial license, please open an issue or contact the author.

Note: because it restricts commercial use, this is not an OSI-approved "open source" license.
