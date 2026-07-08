# Vendor Downloader - Manual + Automated Hybrid

Since vendor sites use varying authentication/bot-blocking, use this workflow:

## Quick Manual Download (Most Reliable)

For each vendor in VENDOR_TARGETS.md:

### Biostar (Start Here)
1. Visit: https://www.biostar.com.tw/app/en/mb/support.php
2. Select motherboard → Download → Look for "OC Utility" or "Chipset"
3. Save to: `C:\Users\macin\Desktop\vuln\downloads\Biostar_*.exe`

### Thermalright
1. Visit: https://www.thermalright.com/
2. Find "Downloads" or "Products" → Cooling software
3. Look for fan controller or monitoring tool .exe
4. Save to: `C:\Users\macin\Desktop\vuln\downloads\Thermalright_*.exe`

### ASRock
1. Visit: https://www.asrock.com/
2. Support → Drivers & Utilities
3. Download "OC Utility" or "Chipset" utilities
4. Save to: `C:\Users\macin\Desktop\vuln\downloads\ASRock_*.exe`

### Kingston
1. Visit: https://www.kingston.com/en/support
2. Find SSD management tool (e.g., Kingston FURY Beast Manager)
3. Save to: `C:\Users\macin\Desktop\vuln\downloads\Kingston_*.exe`

### Patriot
1. Visit: https://www.patriotmemory.com/en-US
2. Support → Find SSD/Storage utility software
3. Save to: `C:\Users\macin\Desktop\vuln\downloads\Patriot_*.exe`

## Once Downloaded: Auto-Analyze

After you've downloaded 5-10 installers to `./downloads/`:

```powershell
cd C:\Users\macin\Desktop\vuln
python tools/extract_drivers.py ./downloads ./extracted_drivers ./data/checked_hashes.json
python tools/batch_analyze.py ./extracted_drivers --min-score 4 --min-ioctl 1 --output analysis_results.json
```

This will:
1. Extract all .sys files from installers
2. Track hashes (no duplicates)
3. Score each driver (heuristic + IOCTL count)
4. Output JSON with top candidates

Then DrvEye can run on the promising ones.

## Alternative: Direct Download (If Available)

Some vendors have direct links:

```bash
# Biostar OC Utility (may work)
curl -L "https://www.biostar.com.tw/upload/Driver/OC_Utility.zip" -o biostar.zip

# Thermalright (usually no direct link available)
```

Most require manual browser interaction. Manual download is ~10 min for 5 vendors.
