"""Builds assets/oui.json.gz (MAC prefix -> short vendor name) from the IEEE OUI registry.

1. Download https://standards-oui.ieee.org/oui/oui.csv
2. python tools/make_oui.py oui.csv assets/oui.json.gz
"""
import csv, gzip, json, re, sys
src, dst = sys.argv[1], sys.argv[2]
strip = re.compile(r"[,.]?\s*\b(incorporated|inc|corporation|corp|co|ltd|limited|llc|gmbh|s\.?a|b\.?v|ag|oy|ab|plc|company|technologies|technology|electronics|communications|international|industries|systems)\b\.?", re.I)
out = {}
with open(src, newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        name = re.sub(r"\s+", " ", row["Organization Name"]).strip()
        short = name
        for _ in range(3):
            s2 = strip.sub("", short).strip(" ,.-")
            if not s2: break
            short = s2
        out[row["Assignment"].lower()] = short[:40] or name[:40]
with gzip.open(dst, "wt", encoding="utf-8", compresslevel=9) as g:
    json.dump(out, g, separators=(",", ":"))
print(len(out))
