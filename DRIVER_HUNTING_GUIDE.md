# Driver Hunting Methodology & Tracking

## Categories to IGNORE (low/no exploit potential)

- **RGB/LED drivers** — lighting control only, no kernel primitives
- **Thermistor/fan control** — monitor-only, no memory access
- **USB HID peripherals** — keyboard, mouse, headset firmware
- **Audio codec drivers** — DSP only, no kernel access
- **Display adapters** — GPU drivers (separate class, high effort, vendor-specific)
- **Printer drivers** — spooler interaction, no direct kernel primitives
- **Webcam/camera drivers** — video streaming only
- **Network adapters** — packet I/O only (no memory/port access exploits expected)

## High-Value Categories (exploit potential)

- **Chipset utilities** — SMBus, I2C, power management (port I/O, MSR access)
- **Storage/RAID** — disk controller, NVME management (physical memory, DMA)
- **GPU/accelerator** — overclocking tools (memory mapping, register access)
- **CPU tools** — frequency scaling, monitoring (MSR, CPUID manipulation)
- **Platform management** — IPMI, BMC, firmware update (ring 0 access)
- **Virtualization** — Hyper-V, VirtualBox guest drivers (VM escape potential)
- **Anti-cheat/security** — game security (privilege escalation, memory access)
- **Keyboard/input macros** — macro drivers (device I/O control)

## Finding Methods

### ✅ Working Methods

1. **Vendor software downloads** (AIB, utility vendors)
   - Colorful iGameCenter (Inno Setup, contains drivers)
   - EVGA Precision XOC (likely similar structure)
   - MSI Afterburner (GPU/chipset utilities)
   - ASUS GPU Tweak, Gigabyte OC Guru
   - Intel XTU, AMD Ryzen Master variants
   
2. **VT/VirusTotal imphash hunting**
   - Known-vulnerable driver imphash → find variants
   - Example: WinRing0 imphash across versions
   
3. **HEVD samples** (learning/reference)
   - Hacksys Extremely Vulnerable Driver (intentionally vuln)
   - Good for testing analysis pipeline
   
4. **Firmware extraction from products**
   - GPU BIOS/firmware updates often embed drivers
   - Motherboard BIOS extracts (chipset drivers)
   - Solid State Drive firmware (storage drivers)

### ❌ Known Bad Methods

- Generic web search for "Windows drivers" (too much spam, outdated)
- GitHub searching (intentional exploits, already known/cataloged)
- Torrents/warez sites (licensing/ethics issues, low quality)
- Cloudflare-protected sites (respect bot-check pages, don't bypass)

## Extraction Flow

See `tools/extract_drivers.py` for automated extraction.

### Manual Fallback
1. 7-Zip: `7za l <file>` to list contents
2. Inno Setup: `innoextract -l <file>` to list
3. NSIS: UniExtract GUI or 7z attempt
4. Cabinet (.cab): `expand <file> -F:* <output>`

## Analysis Flow

See `tools/batch_analyze.py` for batch processing.

Pipeline:
1. Extract drivers (auto or manual)
2. Verify signatures (`Get-AuthenticodeSignature`)
3. Score heuristically (`drvinspect --score`)
4. Extract IOCTLs (`drvinspect --ioctl`)
5. Filter: keep only score ≥4 and IOCTL count >0
6. Run DrvEye static analysis on survivors
7. Manual reverse engineering on top scorers

## Tracking

- `data/checked_hashes.json` — driver file hashes already analyzed (avoid re-processing)
- `data/checked_websites.json` — websites/vendors fully reviewed (avoid re-checking)
- Update these as you scan new sources

## Current Candidates (~X/30 target)

| SHA256 | Filename | Vendor | Version | Score | DrvEye | Status |
|--------|----------|--------|---------|-------|--------|--------|
| 0fd8b87d... | AMDRyzenMasterDriver.sys | Colorful/AMD | 2.6.0.0 | 8/10 | ✅ BYOVD-ready | Needs dynamic test (CPU gate) |
| 11bd2c9f... | WinRing0x64.sys | Open-source | 1.2.0.5 | 7/10 | ✅ BYOVD-ready | Needs dynamic test (HV boundary) |
| ... | ... | ... | ... | ... | ... | ... |

---

Last updated: [date you last reviewed this]
Next actions: Continue vendor scan, collect to 30 candidates, batch DrvEye pass
