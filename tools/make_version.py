"""Writes assets/version_info.txt (the Windows file-properties block of RamCapper.exe) from VERSION in ramcapper.py.

A proper company / description / version block makes the executable look like what it is to Windows and to antivirus
heuristics (unsigned executables without it are treated more suspiciously). build.bat runs this before PyInstaller.
"""
import os
import re

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
src = open(os.path.join(root, "ramcapper.py"), encoding="utf-8").read()
ver = re.search(r'^VERSION = "([\d.]+)"', src, re.M).group(1)
parts = (ver.split(".") + ["0", "0", "0", "0"])[:4]
tup = ", ".join(parts)
dotted = ".".join(parts)
text = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({tup}), prodvers=({tup}), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'tekno-lab'),
      StringStruct('FileDescription', 'RamCapper - RAM monitor and limiter'),
      StringStruct('FileVersion', '{dotted}'),
      StringStruct('InternalName', 'RamCapper'),
      StringStruct('LegalCopyright', 'PolyForm Noncommercial License 1.0.0'),
      StringStruct('OriginalFilename', 'RamCapper.exe'),
      StringStruct('ProductName', 'RamCapper'),
      StringStruct('ProductVersion', '{dotted}'),
      StringStruct('Comments', 'https://github.com/tekno-lab/ramcapper')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ])
"""
with open(os.path.join(root, "assets", "version_info.txt"), "w", encoding="utf-8") as f:
    f.write(text)
print("version", dotted)
