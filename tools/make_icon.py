"""Regenerates assets/ramcapper.ico and assets/icon.png from assets/icon.svg.

Needs Pillow (pip install pillow) and Microsoft Edge (used as the SVG rasterizer).
Run from the repository root:  python tools/make_icon.py
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SVG = ROOT / "assets" / "icon.svg"
EDGE = next((p for p in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                         r"C:\Program Files\Microsoft\Edge\Application\msedge.exe") if os.path.exists(p)), None)
if not EDGE:
    sys.exit("Microsoft Edge not found")

with tempfile.TemporaryDirectory() as tmp:
    page = Path(tmp) / "icon.html"
    page.write_text(f"<html><body style='margin:0;background:transparent'>{SVG.read_text(encoding='utf-8')}</body></html>", encoding="utf-8")
    png = Path(tmp) / "icon_512.png"
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--default-background-color=00000000",
                    "--window-size=512,512", f"--screenshot={png}", page.as_uri()], check=True, capture_output=True)
    img = Image.open(png).convert("RGBA")

img.save(ROOT / "assets" / "ramcapper.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
img.resize((256, 256), Image.LANCZOS).save(ROOT / "assets" / "icon.png")
print("wrote assets/ramcapper.ico and assets/icon.png")
