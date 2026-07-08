"""Search a large binary blob (e.g. an Electron app.asar) for driver/kernel
access strings, to see what native mechanism an app uses for hardware access
without needing to unpack or execute it."""
import re
import sys

path = sys.argv[1]
data = open(path, "rb").read()
print(f"scanned {len(data):,} bytes")

patterns = [
    rb"[\w.\\-]{0,30}\.sys\b",
    rb"CreateServiceW?",
    rb"OpenSCManagerW?",
    rb"DeviceIoControl",
    rb"WinRing0[\w]*",
    rb"IOCTL_[A-Z_]+",
    rb"\\\\\.\\[\w]+",
    rb"[\w]{0,20}[Dd]river[\w]{0,20}",
]

for pat in patterns:
    found = set(re.findall(pat, data))
    if found:
        print(f"\n=== {pat.decode(errors='replace')} ({len(found)} unique) ===")
        for m in sorted(found)[:15]:
            print(" ", m[:100])
