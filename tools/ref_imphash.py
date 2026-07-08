"""Print the reference imphash (via pefile) for drivers, to validate our C++."""
import glob
import os
import sys

import pefile

paths = sys.argv[1:] or sorted(
    glob.glob(r"C:\Windows\System32\drivers\*.sys"))[:6]
for p in paths:
    try:
        pe = pefile.PE(p, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        print((pe.get_imphash() or "(none)"), os.path.basename(p))
    except Exception as e:
        print("ERR", os.path.basename(p), e)
