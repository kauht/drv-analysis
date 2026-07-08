#!/usr/bin/env python3
"""Flatten the LOLDrivers metadata JSON into a compact TSV signature database.

The C++ detector loads this TSV directly, so it needs no JSON library. Each
output row is one *sample* (a driver file) with its hashes and the facts we
use for a verdict. One catalog entry can list several samples, so rows > entries.

Usage: python tools/build_db.py data/loldrivers.json data/loldrivers_db.tsv
"""
import json
import sys

COLUMNS = ["sha256", "sha1", "md5", "category", "filename",
           "publisher", "loads_despite_hvci", "imphash"]


def clean(value: str) -> str:
    """Normalise a field: strip, drop tabs/newlines, lowercase-safe caller."""
    if value is None:
        return ""
    return str(value).replace("\t", " ").replace("\n", " ").strip()


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else "data/loldrivers.json"
    dst = sys.argv[2] if len(sys.argv) > 2 else "data/loldrivers_db.tsv"

    data = json.load(open(src, encoding="utf-8"))
    rows = []
    for entry in data:
        category = clean(entry.get("Category"))
        for sample in entry.get("KnownVulnerableSamples") or []:
            sha256 = clean(sample.get("SHA256")).lower()
            sha1 = clean(sample.get("SHA1")).lower()
            md5 = clean(sample.get("MD5")).lower()
            # Skip samples with no hash at all -- nothing to match on.
            if not (sha256 or sha1 or md5):
                continue
            rows.append([
                sha256, sha1, md5, category,
                clean(sample.get("Filename")),
                clean(sample.get("Publisher")),
                clean(sample.get("LoadsDespiteHVCI")),
                clean(sample.get("Imphash")).lower(),
            ])

    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        f.write("\t".join(COLUMNS) + "\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    with_sha256 = sum(1 for r in rows if r[0])
    print(f"entries read   : {len(data)}")
    print(f"samples written: {len(rows)}")
    print(f"  with sha256  : {with_sha256}")
    print(f"wrote {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
