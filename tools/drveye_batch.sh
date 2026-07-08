#!/usr/bin/env bash
# Run DrvEye against every unique .sys file collected this session and
# extract the key triage fields (signature status, load verdict, bug tags)
# into one consolidated report.
set -u
cd "$(dirname "$0")/.."

DRVEYE="tools/drveye/venv/Scripts/python.exe"
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

FILES=(
  "samples/HEVD/driver/secure/x64/HEVD.sys"
  "samples/HEVD/driver/secure/x86/HEVD.sys"
  "samples/HEVD/driver/vulnerable/x64/HEVD.sys"
  "samples/HEVD/driver/vulnerable/x86/HEVD.sys"
  "samples/colorful/drivers/app/Driver/Earphone/Sentry/Driver/drivers/Package/x64/FE_H24.sys"
  "samples/colorful/drivers/app/WinRing0x64.sys"
  "samples/colorful/drivers/app/iGameAPI/MBoardOverclock/AMD_RyzenMaster/AMDRyzenMasterDriver.sys"
  "samples/colorful/drivers/app/iGameAPI/Notebook/NotebookSDK/Clevo/ClevoDCHUDriver/AMDRyzenMasterDriver.sys"
  "samples/colorful/drivers/app/iGameAPI/Notebook/NotebookSDK/Clevo/ClevoDCHUDriver/AcpiBridge.sys"
  "samples/colorful/drivers/app/iGameAPI/Notebook/NotebookSDK/Clevo/ClevoDCHUDriver/AcpiBridge1.sys"
  "samples/colorful/drivers/app/iGameDNADriver/x64/IGAME_DNA.sys"
  "samples/colorful/drivers/app/iGameDNAsDriver/x64/IGAME_DNAS.sys"
  "samples/coolermaster/drivers/app/cm_drv_installer/CM_MHGS/Win10/x64/CMTAC.sys"
  "samples/coolermaster/drivers/app/cm_drv_installer/cmedia_108b/win10/X64/CMUAC.sys"
  "samples/coolermaster/drivers/app/cm_drv_installer/cmedia_108b/win7/X64/CMUAC.sys"
  "samples/pny/extracted/FrameView/bin/FrameViewKMD.sys"
  "samples/thermaltake/drivers/TT021-00-0_FW_V1.0.5.4.sys"
  "samples/thermaltake/drivers/TT039-00-0_FW_V1.0.5.4.sys"
)

OUT="tools/drveye_batch_results"
mkdir -p "$OUT"

for f in "${FILES[@]}"; do
  base=$(basename "$f" | tr '/\\ ' '___')
  outfile="$OUT/${base}.txt"
  echo "=== analyzing: $f ==="
  "$DRVEYE" tools/drveye/DrvEye.py "$f" > "$outfile" 2>&1
  echo "  -> $outfile"
done

echo ""
echo "################ CONSOLIDATED SUMMARY ################"
printf "%-45s %-12s %-40s %s\n" "FILE" "SIGNED" "LOAD VERDICT (Default Win10/11)" "BUG TAGS FOUND"
for f in "${FILES[@]}"; do
  base=$(basename "$f" | tr '/\\ ' '___')
  outfile="$OUT/${base}.txt"
  name=$(basename "$f")

  if grep -q "not a valid PE\|PE Analysis Failed\|Traceback" "$outfile" 2>/dev/null; then
    printf "%-45s %-12s %-40s %s\n" "$name" "N/A" "NOT A VALID PE / ERROR" "-"
    continue
  fi

  sig="?"
  if grep -q "UNSIGNED" "$outfile"; then sig="UNSIGNED"
  elif grep -q "SELF-SIGNED" "$outfile"; then sig="SELF-SIGNED"
  elif grep -q "kernel-trusted" "$outfile"; then sig="TRUSTED"
  elif grep -q "Authenticode Signature" "$outfile"; then sig="signed?"
  fi

  verdict=$(grep -A1 "Default Win10/11" "$outfile" | head -1 | sed -E 's/.*(WILL LOAD|WILL NOT LOAD).*/\1/')
  [ -z "$verdict" ] && verdict="?"

  bugs=$(grep -oE "bugs=[a-z,-]+" "$outfile" | sort -u | tr '\n' ';' | sed 's/;$//')
  [ -z "$bugs" ] && bugs="none found"

  printf "%-45s %-12s %-40s %s\n" "$name" "$sig" "$verdict" "$bugs"
done
