# drv-analysis

Windows driver vulnerability research toolkit. Analyzes drivers for BYOVD (Bring-Your-Own-Vulnerable-Driver) exploitation primitives including exploitable IOCTLs, physical memory access, and kernel-level attack surfaces.

## drvinspect

C++ driver analysis tool supporting:
- PE format parsing (imports, exports, sections)
- Authenticode signature verification
- IOCTL code extraction and analysis
- Call-graph walking via disassembly (x64 via Zydis)
- Heuristic vulnerability scoring
- LOLDrivers database integration

### Building

Requires `xmake` build system:
```
xmake build
```

Output binary: `build/windows/x64/debug/drvinspect.exe`

### Usage

```
drvinspect <driver.sys> [--check] [--score] [--ioctl] [--yaml] [--json]
```

### Features

- `--check`: Verify Authenticode signature validity
- `--score`: Heuristic BYOVD candidate scoring (0-10)
- `--ioctl`: Extract IOCTL codes and compute CTL_CODE macro decomposition
- `--yaml`: Generate LOLDrivers YAML entry template
- `--json`: Output structured analysis results

## Tools

- `tools/7z/` - 7-Zip portable utilities (archive extraction)
- `tools/innoextract/` - Inno Setup installer extraction
- `tools/drveye_batch_results/` - Static analysis results from DrvEye (reachability analysis, exploit primitives)
- `tools/triage.py` - Driver triage pipeline
- `tools/find_xrefs.py` - Cross-reference analysis (pefile + capstone)
- `tools/ref_dispatch.py` - IOCTL dispatch table extraction

## Data

- `data/loldrivers.json` - LOLDrivers database
- `data/loldrivers_db.tsv` - Flattened TSV format for analysis

## Contributing

This project is part of LOLDrivers vulnerability research. New driver findings should be documented in LOLDrivers YAML format and submitted via pull request.

## Security Notice

This tool is intended for defensive security research and authorized testing only. Drivers analyzed here may contain real vulnerabilities exploitable for privilege escalation or kernel-level attacks. Use responsibly in controlled lab environments.
