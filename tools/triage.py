"""Hardened triage for candidate drivers: runs DrvEye (JSON mode) and applies
a KEEP/DELETE verdict + confidence score, so we stop manually re-deriving the
same judgment call for every new sample.

Two-stage logic:
1. HARD GATE (score forced to 0, always DELETE) -- the driver can't function
   as a real BYOVD vector at all, regardless of what bugs it has:
     - not a valid PE
     - unsigned / self-signed (incl. WDK test certs)
     - signature chain doesn't anchor to a Microsoft-trusted kernel root
     - blocked even under the "Secure Boot + DSE" baseline (the realistic
       default for most target machines -- NOT the same as being blocked
       only by HVCI, which most systems don't run and is expected/normal
       for this whole class of driver, e.g. WinRing0 itself)

2. CONFIDENCE SCORE (0-100) for anything that passes the hard gate:
     +60  at least one IOCTL has a confirmed primitive (physical-rw, msr-rw,
          port-io, process-kill, etc.) -- this is the "matters" signal the
          user asked for: physical-memory-class primitives, not just any bug
     +20  a primitive-bearing IOCTL also shows "WITHOUT security checks" in
          its risk factors (DrvEye's ungated-sink signal)
     +20  DrvEye emitted a concrete named exploit_chain
   With NO primitive at all (only double-fetch/missing-probe/length-unbounded
   -- bugs that need real exploit dev to prove anything and "usually don't
   matter" per the user), the score caps at 15: under the 50% bar, DELETE.

Usage: python triage.py <driver.sys> [<driver.sys> ...]
       python triage.py --dir <directory>   (recursively finds all .sys files)
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
DRVEYE_PY = HERE / "drveye" / "DrvEye.py"
DRVEYE_PYTHON = HERE / "drveye" / "venv" / "Scripts" / "python.exe"
JSON_TMP_DIR = HERE / "triage_json"

CONFIDENCE_KEEP_THRESHOLD = 50


def run_drveye(path: Path) -> dict | None:
    JSON_TMP_DIR.mkdir(exist_ok=True)
    out = JSON_TMP_DIR / (path.stem.replace(" ", "_") + f"_{abs(hash(str(path)))}.json")
    env_cmd = [str(DRVEYE_PYTHON), str(DRVEYE_PY), str(path), "--json", str(out), "--no-color"]
    import os
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        subprocess.run(env_cmd, capture_output=True, timeout=180, env=env)
    except subprocess.TimeoutExpired:
        return None
    if not out.exists():
        return None
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def hard_gate_fails(d: dict) -> str | None:
    """Return a reject reason string, or None if the driver passes the gate."""
    cert = d.get("certificate") or {}
    if not cert.get("signed"):
        return "unsigned"
    if cert.get("signer_self_signed"):
        return "self-signed (incl. test cert)"
    anchor = cert.get("chain_anchor")
    if not anchor or not anchor.get("trusted_for_kernel"):
        return "signature chain not anchored to a kernel-trusted MS root"
    blockers = (d.get("load_verdict") or {}).get("blockers") or []
    if "Secure Boot" in blockers:
        return "blocked even under Secure Boot + DSE baseline"
    return None


# bug_classes tags that indicate a REAL dangerous primitive (memory/hardware
# access gone wrong), vs. secondary/hard-to-weaponize classes that "usually
# don't matter" on their own (double-fetch, missing-probe, length-unbounded).
PRIMITIVE_BUG_CLASSES = {"arbitrary-rw", "arbitrary-read", "arbitrary-write",
                         "msr-rw", "port-io-rw", "process-kill", "token-theft"}
# ioctl.purpose strings that indicate hardware/memory access even when
# bug_classes wasn't populated for this specific IOCTL.
DANGEROUS_PURPOSES = {"phys mem map", "port i/o", "msr access", "process access"}

# KNOWN FALSE POSITIVE: CPUID vendor-string constants ("GenuineIntel",
# "AuthenticAMD"), split across EBX/EDX/ECX after a CPUID call, get
# misidentified as IOCTL dispatch comparisons by DrvEye's pattern scanner --
# confirmed by hand on CMTAC.sys (0x756E6547 = "Genu" -> primitives=
# ['arbitrary-read','arbitrary-write'] plus a fabricated "Token Steal via
# Arbitrary R/W" exploit_chain, even though it's just an Intel/AMD CPU check
# in DriverEntry, not a real user-reachable code path at all). Any IOCTL
# "code" matching one of these MUST be ignored, however confident-looking its
# tags are -- do not extend this allowlist without re-verifying the same way
# (decode the hex as little-endian ASCII, check for CPUID substrings).
_CPUID_VENDOR_CODES = {
    0x756E6547, 0x49656E69, 0x6C65746E,  # "Genu" "ineI" "ntel" (GenuineIntel)
    0x68747541, 0x69746E65, 0x444D4163,  # "Auth" "enti" "cAMD" (AuthenticAMD)
}


def _is_cpuid_false_positive(code_str: str) -> bool:
    try:
        return int(code_str, 16) in _CPUID_VENDOR_CODES
    except (TypeError, ValueError):
        return False


def score(d: dict) -> tuple[int, list[str]]:
    reasons = []
    ioctls = d.get("ioctls") or []

    # Two independent signals for "this IOCTL reaches a real primitive" --
    # `primitives` and `bug_classes` are populated by different analysis
    # passes in DrvEye and are NOT always both filled in for the same real
    # finding (confirmed on WinRing0x64.sys: bug_classes=['arbitrary-rw'] on
    # two IOCTLs while primitives stayed [] on all of them). Treat either as
    # sufficient rather than requiring both.
    has_primitive = False
    has_ungated_primitive = False
    skipped_cpuid = 0
    for ioc in ioctls:
        if _is_cpuid_false_positive(ioc.get("code", "")):
            skipped_cpuid += 1
            continue
        prims = ioc.get("primitives") or []
        bugs = set(ioc.get("bug_classes") or [])
        purpose = (ioc.get("purpose") or "").lower()
        is_dangerous = bool(prims) or bool(bugs & PRIMITIVE_BUG_CLASSES) or purpose in DANGEROUS_PURPOSES
        if is_dangerous:
            has_primitive = True
            risk = ((ioc.get("behavior") or {}).get("risk_factors")) or []
            if any("without security checks" in r.lower() for r in risk):
                has_ungated_primitive = True
    if skipped_cpuid:
        reasons.append(f"(ignored {skipped_cpuid} CPUID-vendor-string false-positive IOCTL code(s))")

    # An exploit_chain built ENTIRELY around a CPUID false-positive IOCTL is
    # not real evidence -- only count chains that cite at least one other code.
    real_chains = []
    for chain in (d.get("exploit_chains") or []):
        text = json.dumps(chain)
        cited = {int(c, 16) for c in re.findall(r"IOCTL 0x([0-9A-Fa-f]+)", text)}
        if cited and cited <= _CPUID_VENDOR_CODES:
            reasons.append(f"(ignored exploit_chain '{chain.get('name')}' -- built entirely on a "
                           "CPUID false-positive IOCTL)")
            continue
        real_chains.append(chain)

    # NOTE: originally had a "+40 CRITICAL finding on a call site" fallback
    # here (for drivers with no per-IOCTL primitive but a CRITICAL entry in
    # `findings`). Removed after manual verification showed it's unreliable:
    # on IGAME_DNA.sys it fired on 55+ generic "Integer overflow before
    # ExAllocatePoolWithTag" matches (a common, usually-benign multiply-then-
    # allocate pattern with no attacker-control check) and a "DKOM token
    # steal" match against hardcoded Windows 10 1507 (2015) EPROCESS offsets
    # -- almost certainly coincidental, not confirmed exploitability. Do not
    # re-add a findings-based fallback without hand-verifying it the same way
    # the primitives-based signal was verified (see CPUID false-positive
    # note above).

    total = 0
    if has_primitive:
        total += 60
        reasons.append("+60 confirmed primitive on >=1 IOCTL (physical-rw/msr-rw/port-io/etc., "
                       "via primitives[] or bug_classes)")
    if has_ungated_primitive:
        total += 20
        reasons.append("+20 primitive reachable without security checks (ungated sink)")
    if real_chains:
        total += 20
        reasons.append(f"+20 DrvEye emitted {len(real_chains)} concrete exploit chain(s) "
                       "(excluding CPUID false positives)")

    if not has_primitive:
        total = min(total, 15)
        reasons.append("capped at 15: no confirmed primitive -- only secondary bug classes "
                       "(double-fetch/missing-probe/length-unbounded), which need real exploit "
                       "dev to prove anything and usually don't pan out")
    return min(total, 100), reasons


def triage_one(path: Path) -> dict:
    if not path.exists():
        return {"path": str(path), "verdict": "DELETE", "score": 0, "reasons": ["file not found"]}

    d = run_drveye(path)
    if d is None:
        return {"path": str(path), "verdict": "DELETE", "score": 0,
                "reasons": ["DrvEye could not analyze this file (invalid PE / crash / timeout)"]}

    reject = hard_gate_fails(d)
    if reject:
        return {"path": str(path), "verdict": "DELETE", "score": 0, "reasons": [f"hard gate: {reject}"]}

    conf, reasons = score(d)
    verdict = "KEEP" if conf >= CONFIDENCE_KEEP_THRESHOLD else "DELETE"
    return {"path": str(path), "verdict": verdict, "score": conf, "reasons": reasons,
            "sha256": d.get("sha256"), "attack_risk": d.get("attack_risk")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--dir")
    args = ap.parse_args()

    files = [Path(p) for p in args.paths]
    if args.dir:
        files += sorted(Path(args.dir).rglob("*.sys"))

    results = [triage_one(f) for f in files]

    print(f"{'VERDICT':<8}{'SCORE':<7}{'FILE'}")
    for r in results:
        print(f"{r['verdict']:<8}{r['score']:<7}{r['path']}")
        for reason in r["reasons"]:
            print(f"           {reason}")

    keep = [r for r in results if r["verdict"] == "KEEP"]
    delete = [r for r in results if r["verdict"] == "DELETE"]
    print(f"\n{len(keep)} KEEP, {len(delete)} DELETE (of {len(results)} analyzed)")

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
