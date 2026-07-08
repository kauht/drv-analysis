"""Re-apply triage.py's (fixed) scoring logic to already-cached DrvEye JSON
results in tools/triage_json/, without re-running the expensive emulation."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from triage import hard_gate_fails, score  # noqa: E402

JSON_DIR = Path(__file__).parent / "triage_json"

# sha256 -> a representative original file path, so results map back cleanly.
KNOWN_PATHS = {
    "0fd8b87d79828282a2b24c0680ecf6717c3bc284582af552ecea8d2e79c91b4b":
        "samples/colorful/drivers/app/iGameAPI/MBoardOverclock/AMD_RyzenMaster/AMDRyzenMasterDriver.sys (v2.6.0.0, UNLISTED LEAD)",
    "4a0d0034f6deabb9369f553d4d9f3a7aa6f87fa8f2292be576d7b42897c686bb":
        "AMDRyzenMasterDriver.sys (v1.7.0.0, known-bad CVE-2023-20564)",
    "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5":
        "WinRing0x64.sys (known-bad)",
    "83986d972914a60e76772ce93c2809cedbd224ca9a4fcb8f13c86e49af40fbe9":
        "CMTAC.sys (Cooler Master, win7+win10 x64 identical)",
    "4420460d71481426334e221d9a3fa1d4ff2f493c88cb5791ce46961faaa725db":
        "IGAME_DNA.sys (Colorful)",
    "2e8dde1c73789df9e846f844de47558363e1ce317555a01da0af3ea7989600c5":
        "IGAME_DNAS.sys (Colorful)",
}

seen = {}
for jf in JSON_DIR.glob("*.json"):
    try:
        d = json.loads(jf.read_text(encoding="utf-8"))
    except Exception:
        continue
    sha = d.get("sha256")
    if not sha or sha in seen:
        continue
    seen[sha] = d

print(f"{'VERDICT':<8}{'SCORE':<7}{'FILE'}")
for sha, d in seen.items():
    reject = hard_gate_fails(d)
    if reject:
        verdict, conf, reasons = "DELETE", 0, [f"hard gate: {reject}"]
    else:
        conf, reasons = score(d)
        verdict = "KEEP" if conf >= 50 else "DELETE"
    label = KNOWN_PATHS.get(sha, sha)
    print(f"{verdict:<8}{conf:<7}{label}")
    for r in reasons:
        print(f"           {r}")
