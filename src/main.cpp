#include "disasm.hpp"
#include "hashing.hpp"
#include "heuristics.hpp"
#include "pe.hpp"
#include "sigdb.hpp"
#include "yamlgen.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;
using namespace drvinspect;

namespace {

// Kernel APIs commonly abused by vulnerable/malicious drivers. Importing one
// of these doesn't prove a driver is dangerous, but it's exactly the signal a
// LOLDrivers triager looks for: primitives for arbitrary physical-memory
// access, killing protected processes, or loading unsigned code.
const std::unordered_set<std::string>& dangerous_apis() {
    static const std::unordered_set<std::string> apis = {
        "MmMapIoSpace", "MmMapIoSpaceEx", "MmUnmapIoSpace",
        "MmGetPhysicalAddress", "MmMapLockedPagesSpecifyCache",
        "ZwMapViewOfSection", "MmCopyMemory",
        "READ_PORT_UCHAR", "WRITE_PORT_UCHAR",
        "ZwTerminateProcess", "ZwOpenProcess", "PsLookupProcessByProcessId",
        "ZwProtectVirtualMemory", "KeStackAttachProcess",
        "__readmsr", "__writemsr",
        "ZwLoadDriver", "ObRegisterCallbacks",
    };
    return apis;
}

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                std::istreambuf_iterator<char>());
}

const char* machine_name(uint16_t m) {
    switch (m) {
        case 0x014c: return "x86 (i386)";
        case 0x8664: return "x64 (AMD64)";
        case 0xaa64: return "ARM64";
        case 0x01c0: return "ARM";
        default:     return "unknown";
    }
}

// Everything we learn about one file, in one place, so single-file and scan
// modes share the exact same analysis.
struct FileReport {
    bool readable = false;
    std::string path;
    size_t size = 0;
    FileHashes hashes;
    FileHashes authentihash;  // valid whenever pe is set
    std::optional<PeInfo> pe;
    SigRecord match;   // valid == true if a file hash matched the DB
    RiskReport risk;   // populated when scored
    bool scored = false;
    DispatchAnalysis dispatch;  // populated when ioctl == true
    bool did_ioctl = false;
};

FileReport analyze(const std::string& path, const SignatureDb* db, bool score,
                   bool ioctl) {
    FileReport r;
    r.path = path;
    std::vector<uint8_t> data = read_file(path);
    if (data.empty())
        return r;
    r.readable = true;
    r.size = data.size();
    r.hashes = compute_hashes(data);
    if (db)
        r.match = db->match(r.hashes);
    r.pe = parse_pe(data);
    if (r.pe)
        r.authentihash = compute_authentihash(data, *r.pe);
    if (score && r.pe) {
        r.risk = score_driver(*r.pe, db);
        r.scored = true;
    }
    if (ioctl && r.pe) {
        r.dispatch = analyze_dispatch(data, *r.pe);
        r.did_ioctl = true;
    }
    return r;
}

// Roll the two detection layers into one verdict. Severity: 3 = known-bad by
// hash (certain), 2 = imphash variant of a known-bad (strong), 1 = suspicious
// shape (review), 0 = nothing notable.
struct Verdict {
    int severity = 0;
    std::string label;   // short, for the scan table
    std::string detail;  // longer, for single-file output
};

Verdict verdict_for(const FileReport& r) {
    Verdict v;
    // did_ioctl + found_dispatch + (a reachable primitive or raw METHOD_NEITHER
    // input) is the strongest static signal short of a hash/imphash match: it
    // means the DEVICE_CONTROL handler itself -- not just the import table --
    // carries the dangerous shape. Still not proof (no argument-taint tracing
    // yet), but it's the "reachable", not merely "capable", case from our
    // IOCTL-analysis discussion.
    bool confirmed_reachable = r.did_ioctl && r.dispatch.found_dispatch &&
                               (!r.dispatch.primitive_calls.empty() ||
                                r.dispatch.method_neither);

    if (r.match.valid) {
        v.severity = 4;
        v.label = "KNOWN-BAD";
        v.detail = "matches a LOLDrivers entry (" + r.match.category + ")";
    } else if (r.scored && r.risk.imphash_match) {
        v.severity = 3;
        v.label = "IMPHASH-VAR";
        v.detail = "imphash matches a known-bad sample (likely a " +
                   r.risk.imphash_match_category + " variant)";
    } else if (confirmed_reachable) {
        v.severity = 2;
        v.label = "REACHABLE";
        if (!r.dispatch.primitive_calls.empty() && r.dispatch.method_neither)
            v.detail = "DEVICE_CONTROL handler reaches a kernel primitive AND "
                       "takes raw METHOD_NEITHER input";
        else if (!r.dispatch.primitive_calls.empty())
            v.detail = "DEVICE_CONTROL handler reaches an imported kernel "
                       "primitive";
        else
            v.detail = "DEVICE_CONTROL handler exposes METHOD_NEITHER IOCTLs "
                       "(raw, unvalidated user pointers)";
    } else if (r.scored && r.risk.score >= 6) {
        v.severity = 1;
        v.label = "SUSPICIOUS";
        v.detail = "high capability score (" + std::to_string(r.risk.score) +
                   "/10) -- review the IOCTL handler";
    } else {
        v.severity = 0;
        v.label = "unknown";
        v.detail = r.scored ? "no strong signal (score " +
                                  std::to_string(r.risk.score) + "/10)"
                            : "not a known bad file";
    }
    return v;
}

void print_ioctl(const DispatchAnalysis& d) {
    std::printf("\n[ioctl] dispatch analysis\n");
    if (!d.supported) {
        std::printf("  unsupported (x64 driver with a code section required)\n");
        return;
    }
    if (!d.found_dispatch) {
        std::printf("  IRP_MJ_DEVICE_CONTROL handler not located "
                    "(indirect/loop table setup not yet handled)\n");
        return;
    }
    std::printf("  device-control handler : +0x%08x\n", d.device_control_rva);
    std::printf("  secure device (ACL)    : %s\n",
                d.secure_device ? "yes (IoCreateDeviceSecure)"
                                : "no / not detected");
    if (!d.ioctl_codes.empty()) {
        std::printf("  IOCTL codes seen       : ");
        for (size_t i = 0; i < d.ioctl_codes.size() && i < 12; ++i)
            std::printf("0x%08x ", d.ioctl_codes[i]);
        std::printf("\n");
    }
    std::printf("  METHOD_NEITHER IOCTL   : %s\n",
                d.method_neither ? "YES -- raw unvalidated user pointers" : "no");
    if (d.primitive_calls.empty()) {
        std::printf("  reachable primitives   : none imported/called in graph\n");
    } else {
        std::printf("  !! reachable primitives (in handler call-graph):\n");
        for (const auto& c : d.primitive_calls)
            std::printf("       %s\n", c.c_str());
    }
    // Describe precisely what we found -- don't claim a primitive we didn't see.
    if (!d.primitive_calls.empty() && d.method_neither)
        std::printf("  => handler reaches a kernel primitive AND takes raw "
                    "METHOD_NEITHER input -- strong BYOVD indicator.\n");
    else if (!d.primitive_calls.empty())
        std::printf("  => handler reaches an imported kernel primitive -- "
                    "review how its arguments are validated.\n");
    else if (d.method_neither)
        std::printf("  => handler exposes METHOD_NEITHER IOCTLs (raw, "
                    "unvalidated user pointers) -- review by hand.\n");
}

void print_full(const FileReport& r, bool did_check, bool did_score) {
    std::printf("== drvinspect ==\n");
    std::printf("file : %s\n", r.path.c_str());
    std::printf("size : %zu bytes\n\n", r.size);

    std::printf("[hashes]\n");
    std::printf("  MD5    : %s\n", r.hashes.md5.c_str());
    std::printf("  SHA1   : %s\n", r.hashes.sha1.c_str());
    std::printf("  SHA256 : %s\n", r.hashes.sha256.c_str());
    if (r.pe) {
        std::printf("  Authentihash MD5    : %s\n", r.authentihash.md5.c_str());
        std::printf("  Authentihash SHA1   : %s\n", r.authentihash.sha1.c_str());
        std::printf("  Authentihash SHA256 : %s\n", r.authentihash.sha256.c_str());
    }
    std::printf("\n");

    if (did_check) {
        std::printf("[verdict]\n");
        if (r.match.valid) {
            std::printf("  !! KNOWN BAD -- matches a LOLDrivers entry\n");
            std::printf("     category  : %s\n", r.match.category.c_str());
            if (!r.match.filename.empty())
                std::printf("     filename  : %s\n", r.match.filename.c_str());
            if (!r.match.publisher.empty())
                std::printf("     publisher : %s\n", r.match.publisher.c_str());
            if (!r.match.loads_despite_hvci.empty())
                std::printf("     HVCI bypass: %s\n",
                            r.match.loads_despite_hvci.c_str());
        } else {
            std::printf("  not in the LOLDrivers dataset (unknown file)\n");
        }
        std::printf("\n");
    }

    if (!r.pe) {
        std::printf("[pe] not a valid PE image (no MZ/PE signature)\n");
    } else {
        const PeInfo& pe = *r.pe;
        std::printf("[pe]\n");
        std::printf("  arch      : %s (%d-bit)\n", machine_name(pe.machine),
                    pe.is_64bit ? 64 : 32);
        std::printf("  timestamp : 0x%08x\n", pe.timestamp);
        std::printf("  subsystem : %u%s\n", pe.subsystem,
                    pe.subsystem == 1 ? " (native / driver)" : "");
        std::printf("  sections  : %zu\n", pe.sections.size());
        for (const auto& s : pe.sections)
            std::printf("    %-8s  va=0x%08x  vsize=0x%-8x rawsize=0x%x\n",
                        s.name.c_str(), s.virtual_address, s.virtual_size,
                        s.raw_size);
        std::printf("\n");

        std::printf("[imports] %zu symbols\n", pe.imports.size());
        std::vector<const ImportedSymbol*> flagged;
        for (const auto& sym : pe.imports)
            if (!sym.by_ordinal && dangerous_apis().count(sym.name))
                flagged.push_back(&sym);
        if (flagged.empty()) {
            std::printf("  (no notably dangerous kernel APIs matched)\n");
        } else {
            std::printf("  !! %zu potentially dangerous API(s):\n",
                        flagged.size());
            for (const auto* sym : flagged)
                std::printf("     %-30s from %s\n", sym->name.c_str(),
                            sym->dll.c_str());
        }
    }

    if (did_score && r.scored) {
        std::printf("\n[risk] score %d/10 (%s)\n", r.risk.score,
                    r.risk.band.c_str());
        std::printf("  imphash : %s\n",
                    r.risk.imphash.empty() ? "(none)" : r.risk.imphash.c_str());
        if (r.risk.factors.empty())
            std::printf("  no BYOVD-relevant capabilities detected\n");
        else
            for (const auto& f : r.risk.factors)
                std::printf("  +%d  %s\n", f.points, f.description.c_str());
    }

    if (r.did_ioctl)
        print_ioctl(r.dispatch);

    // Combined bottom-line verdict whenever we did any detection.
    if (did_check || did_score || r.did_ioctl) {
        Verdict v = verdict_for(r);
        std::printf("\n[summary] %s -- %s\n", v.label.c_str(),
                    v.detail.c_str());
        if (v.severity >= 1)
            std::printf("  note: heuristic signal is not proof; confirm by "
                        "reviewing the driver's IOCTL handler.\n");
    }
}

int run_scan(const std::string& dir, const SignatureDb& db, bool deep) {
    std::printf("scanning '%s' ...%s\n", dir.c_str(),
                deep ? " (deep: IOCTL dispatch analysis, slower)" : "");
    std::printf("%-12s %-6s %s\n", "VERDICT", "SCORE", "FILE");

    int total = 0, flagged = 0;
    std::error_code ec;
    // skip_permission_denied so a locked subdirectory doesn't abort the walk.
    fs::recursive_directory_iterator it(
        dir, fs::directory_options::skip_permission_denied, ec), end;
    if (ec) {
        std::fprintf(stderr, "error: cannot scan '%s': %s\n", dir.c_str(),
                     ec.message().c_str());
        return 1;
    }
    while (it != end) {
        std::error_code fec;
        bool is_file = it->is_regular_file(fec);
        std::string p = it->path().string();
        std::string ext = it->path().extension().string();

        it.increment(ec);  // advance first; recover instead of aborting
        if (ec) {
            it.pop(ec);     // skip the subtree we couldn't descend
            if (ec)
                break;      // truly stuck -- stop rather than spin
            continue;
        }
        if (!is_file || fec)
            continue;
        for (char& c : ext) c = static_cast<char>(std::tolower(c));
        if (ext != ".sys")
            continue;

        FileReport r = analyze(p, &db, /*score=*/true, /*ioctl=*/deep);
        if (!r.readable)
            continue;
        ++total;
        Verdict v = verdict_for(r);
        if (v.severity >= 1) {
            ++flagged;
            std::printf("%-12s %2d/10  %s\n", v.label.c_str(),
                        r.scored ? r.risk.score : 0, p.c_str());
        }
    }
    std::printf("\nscanned %d driver(s); %d flagged for review.\n", total,
                flagged);
    return 0;
}

void usage() {
    std::fprintf(stderr,
        "usage:\n"
        "  drvinspect <driver.sys> [--check] [--score] [--ioctl] [--yaml] [--db <path>]\n"
        "  drvinspect --scan <dir> [--ioctl] [--db <path>]\n"
        "\n"
        "  --check   look the file up in the LOLDrivers signature DB\n"
        "  --score   heuristic BYOVD risk score (capability analysis)\n"
        "  --ioctl   disassemble the IOCTL dispatch handler (x64) and trace to\n"
        "            kernel primitives / METHOD_NEITHER input. In --scan mode\n"
        "            this also enables it per file (slower; disassembly-based).\n"
        "  --scan    recursively analyse every .sys under <dir> (loads DB once)\n"
        "  --db      DB path (default: data/loldrivers_db.tsv)\n"
        "  --yaml    emit a DRAFT LOLDrivers yaml entry to stdout instead of the\n"
        "            normal report. Fill in the TODOs before submitting a PR.\n"
        "            Optional metadata overrides (from e.g. Get-Item .VersionInfo\n"
        "            or Get-AuthenticodeSignature -- drvinspect doesn't parse\n"
        "            VERSIONINFO/certificates yet):\n"
        "              --category <vulnerable driver|malicious>\n"
        "              --author <name>          --description <text>\n"
        "              --company <text>         --product <text>\n"
        "              --product-version <ver>  --file-version <ver>\n"
        "              --copyright <text>       --publisher <signer CN>\n"
        "              --resource <url>         (repeatable)\n");
}

} // namespace

int main(int argc, char** argv) {
    std::string path, scan_dir;
    std::string db_path = "data/loldrivers_db.tsv";
    bool do_check = false, do_score = false, do_ioctl = false, do_yaml = false;
    YamlOptions yopts;

    auto need_arg = [&](int& i) -> std::string {
        return (i + 1 < argc) ? std::string(argv[++i]) : std::string();
    };

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--check")            do_check = true;
        else if (a == "--score")       do_score = true;
        else if (a == "--ioctl")       do_ioctl = true;
        else if (a == "--yaml")        do_yaml = true;
        else if (a == "--scan" && i + 1 < argc) scan_dir = argv[++i];
        else if (a == "--db" && i + 1 < argc)   db_path = argv[++i];
        else if (a == "--category" && i + 1 < argc)        yopts.category = need_arg(i);
        else if (a == "--author" && i + 1 < argc)          yopts.author = need_arg(i);
        else if (a == "--description" && i + 1 < argc)     yopts.description = need_arg(i);
        else if (a == "--company" && i + 1 < argc)         yopts.company = need_arg(i);
        else if (a == "--product" && i + 1 < argc)         yopts.product = need_arg(i);
        else if (a == "--product-version" && i + 1 < argc) yopts.product_version = need_arg(i);
        else if (a == "--file-version" && i + 1 < argc)    yopts.file_version = need_arg(i);
        else if (a == "--copyright" && i + 1 < argc)       yopts.copyright = need_arg(i);
        else if (a == "--publisher" && i + 1 < argc)       yopts.publisher = need_arg(i);
        else if (a == "--resource" && i + 1 < argc)        yopts.resources.push_back(need_arg(i));
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "unknown option: %s\n", a.c_str());
            usage();
            return 2;
        } else {
            path = a;
        }
    }

    // The DB is needed for --check, --score's imphash pivot, and all of --scan.
    bool need_db = do_check || do_score || !scan_dir.empty();
    SignatureDb db;
    bool db_loaded = false;
    if (need_db) {
        db_loaded = db.load(db_path);
        if (!db_loaded)
            std::fprintf(stderr,
                "warning: could not open DB '%s' (run tools/build_db.py, or "
                "pass --db)\n", db_path.c_str());
    }

    if (!scan_dir.empty()) {
        if (!db_loaded) {
            std::fprintf(stderr, "error: --scan needs the signature DB\n");
            return 1;
        }
        return run_scan(scan_dir, db, do_ioctl);
    }

    if (path.empty()) {
        usage();
        return 2;
    }

    FileReport r = analyze(path, db_loaded ? &db : nullptr, do_score, do_ioctl);
    if (!r.readable) {
        std::fprintf(stderr, "error: could not read '%s' (missing or empty)\n",
                     path.c_str());
        return 1;
    }

    if (do_yaml) {
        if (!r.pe) {
            std::fprintf(stderr, "error: not a valid PE image, cannot emit yaml\n");
            return 1;
        }
        std::string filename = fs::path(path).filename().string();
        std::vector<uint8_t> data = read_file(path);
        std::fputs(generate_yaml(filename, data, r.hashes, r.authentihash, *r.pe,
                                 yopts).c_str(), stdout);
        return 0;
    }

    print_full(r, do_check, do_score);
    return 0;
}
