"""Fast check: which local drivers share an imphash with a known-bad sample?

This is the Phase-2 imphash pivot, computed in bulk to see whether it would
ever fire on this machine. Uses pefile for imphash and our flattened DB.
"""
import csv
import glob
import os

import pefile

# Load known-bad imphashes -> example (category, filename)
known = {}
with open("data/loldrivers_db.tsv", encoding="utf-8") as f:
    for row in csv.DictReader(f, delimiter="\t"):
        ih = (row.get("imphash") or "").strip().lower()
        if ih:
            known.setdefault(ih, (row["category"], row["filename"]))

print(f"known-bad distinct imphashes: {len(known)}")

hits, scanned, errs = [], 0, 0
for p in glob.glob(r"C:\Windows\System32\drivers\*.sys"):
    try:
        pe = pefile.PE(p, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        ih = (pe.get_imphash() or "").lower()
        scanned += 1
        if ih and ih in known:
            hits.append((os.path.basename(p), ih, known[ih]))
    except Exception:
        errs += 1

print(f"scanned {scanned} local drivers ({errs} unreadable)")
print(f"imphash collisions with known-bad set: {len(hits)}")
for name, ih, (cat, fn) in hits[:25]:
    print(f"  {name:30s} {ih}  ~ {cat} ({fn})")
