# High-Value Vendor Targets (Smaller/Foreign Companies)

These vendors have fewer entries in LOLDrivers but ship drivers with BYOVD potential.

## 🔥 Priority Tier 1 (Chinese/Asian OEMs - High ROI)

### Motherboard/Chipset Tools
- **Colorful (七彩虹)** ✅ Already hit - iGameCenter
- **Biostar** — Overclocking utilities, chipset tools
- **ASRock** — OC utilities (less cataloged than ASUS)
- **JetWay** — Vintage chipset tools
- **Zotac** — GPU + chipset utilities
- **PNY** — OEM storage/GPU tools

### GPU Tools (Non-NVIDIA/AMD)
- **Sapphire** — AMD partners, custom tools
- **Powercolor** — AMD GPU utilities  
- **Gainward** — NVIDIA partners, OC tools
- **Inno3D** — NVIDIA partners
- **Palit** — NVIDIA partners

### Storage/SSD
- **Kingston** — SSD utilities, memory tools
- **Patriot** — SSD management software
- **Crucial/Micron** — Storage encryption/firmware tools
- **Intel** (Data Center) — VROC, storage management

### Thermal/Monitoring
- **Thermalright** — Fan control, thermal monitoring
- **Noctua** — Fan controller utilities
- **Arctic** — Cooling solution management
- **DeepCool** — RGB + thermal tools

### Chipset/Platform (Lesser Known)
- **Realtek** — Audio/network chipset tools (often bundled drivers)
- **Marvell** — Storage controller firmware/utilities
- **LSI** — RAID management (legacy but still shipped)
- **Adaptec** — RAID utilities
- **PMC-Sierra** — Storage arrays

## 🟡 Priority Tier 2 (European/Other Foreign)

- **Gigabyte** (partially cataloged) — More OC tools exist
- **Asus** (partially cataloged) — ROG suite, chipset tools
- **Schenker** (Germany) — Laptop thermal tools
- **Clevo** (Taiwan) — ODM laptop drivers
- **Quanta** (Taiwan) — Server/datacenter tools
- **Wistron** (Taiwan) — Manufacturing platform tools

## 📋 Extraction Points

Most likely installer formats:
- **Inno Setup** (.exe with drivers in subdirs)
- **7-Zip SFX** (auto-extracting archives)
- **NSIS** (Nullsoft installer)
- **RAR SFX** (self-extracting RAR)

## 🚫 Skip / Low ROI
- RGB-only tools (no kernel primitives)
- Display/GPU only (NVIDIA/AMD signed, heavily patched)
- Utility software (no .sys files)
- Thermal fans (read-only sensors)
- Already heavily cataloged (AMD, Intel, Microsoft, NVIDIA, Qualcomm)

## Recommended Hunting Sequence

1. **Colorful** ✅ (already done)
2. **Biostar** (motherboard utilities - high driver density)
3. **Thermalright** (fan + thermal control - physical I/O access)
4. **ASRock** (chipset + OC tools - less cataloged than ASUS)
5. **Kingston** (SSD firmware utilities)
6. **Patriot** (memory/storage tools)
7. **Sapphire** (AMD GPU partner tools)
8. **Zotac** (GPU + chipset hybrid)
9. **Realtek** (audio chipset - often embedded drivers)
10. **Marvell/LSI** (storage controllers - physical memory access)

---

**Note**: After extracting from each vendor, always cross-check SHA256 against LOLDrivers to avoid duplicates.
