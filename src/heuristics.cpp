#include "heuristics.hpp"

#include "hashing.hpp"

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <unordered_set>

namespace drvinspect {
namespace {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

// The imphash spec drops these library extensions before hashing.
std::string strip_lib_ext(std::string dll) {
    dll = lower(dll);
    auto dot = dll.rfind('.');
    if (dot != std::string::npos) {
        std::string ext = dll.substr(dot + 1);
        if (ext == "dll" || ext == "sys" || ext == "ocx")
            dll = dll.substr(0, dot);
    }
    return dll;
}

// True if the driver imports any symbol in `names`.
bool imports_any(const std::unordered_set<std::string>& have,
                 std::initializer_list<const char*> names) {
    for (const char* n : names)
        if (have.count(n))
            return true;
    return false;
}

} // namespace

std::string compute_imphash(const PeInfo& pe) {
    // Build "libname.funcname" for each import, in table order, comma-joined.
    // Ordinal imports become "ordN". (The full spec maps well-known ordinals of
    // ws2_32/oleaut32 to names; drivers import ntoskrnl/hal by name, so that
    // edge case effectively never fires here -- noted as a known limitation.)
    std::string joined;
    bool first = true;
    for (const auto& sym : pe.imports) {
        std::string lib = strip_lib_ext(sym.dll);
        std::string fn = sym.by_ordinal
                             ? "ord" + std::to_string(sym.ordinal)
                             : lower(sym.name);
        if (!first)
            joined.push_back(',');
        joined += lib;
        joined.push_back('.');
        joined += fn;
        first = false;
    }
    if (joined.empty())
        return "";
    return md5_hex(joined);
}

RiskReport score_driver(const PeInfo& pe, const SignatureDb* db) {
    // Index the imports (by exact name) for O(1) capability checks.
    std::unordered_set<std::string> have;
    for (const auto& sym : pe.imports)
        if (!sym.by_ordinal)
            have.insert(sym.name);

    RiskReport r;
    r.imphash = compute_imphash(pe);

    auto add = [&](const std::string& desc, int pts) {
        r.factors.push_back({desc, pts});
        r.score += pts;
    };

    // (a) Reachability: a device object + a user-visible name (symbolic link or
    // device interface) means any process can open it and send IOCTLs. This is
    // the precondition for BYOVD -- primitives are only dangerous if reachable.
    bool creates_device = imports_any(have, {"IoCreateDevice",
                                             "IoCreateDeviceSecure",
                                             "WdmlibIoCreateDeviceSecure"});
    bool user_visible = imports_any(have, {"IoCreateSymbolicLink",
                                           "IoRegisterDeviceInterface"});
    bool reachable = creates_device && user_visible;
    if (reachable)
        add("Exposes a user-openable device (IoCreateDevice + symbolic link) "
            "-- reachable from user mode", 3);

    // (b) Dangerous primitives the reachable code could hit.
    if (imports_any(have, {"MmMapIoSpace", "MmMapIoSpaceEx",
                           "MmGetPhysicalAddress",
                           "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
                           "MmCopyMemory", "ZwMapViewOfSection"}))
        add("Physical/arbitrary memory mapping primitive (kernel read/write)", 3);

    if (imports_any(have, {"__readmsr", "__writemsr"}))
        add("Model-specific register access (__readmsr/__writemsr)", 3);

    if (imports_any(have, {"ZwTerminateProcess", "ZwOpenProcess",
                           "PsLookupProcessByProcessId", "KeStackAttachProcess",
                           "ZwProtectVirtualMemory"}))
        add("Process manipulation primitive (can kill/tamper protected "
            "processes, e.g. EDR/AV)", 2);

    if (imports_any(have, {"READ_PORT_UCHAR", "WRITE_PORT_UCHAR",
                           "READ_PORT_ULONG", "WRITE_PORT_ULONG"}))
        add("Direct hardware port I/O", 1);

    // Synergy note: reachable + a strong primitive is the textbook BYOVD shape.
    bool strong_prim =
        imports_any(have, {"MmMapIoSpace", "MmMapIoSpaceEx", "__writemsr",
                           "MmCopyMemory", "ZwTerminateProcess"});
    if (reachable && strong_prim)
        add("Reachable device leads directly to a kernel primitive "
            "(classic BYOVD shape)", 1);

    // (c) Imphash pivot: shares its import fingerprint with known-bad samples.
    if (db && !r.imphash.empty()) {
        SigRecord ex;
        size_t hits = db->imphash_hits(r.imphash, ex);
        if (hits > 0) {
            r.imphash_match = true;
            r.imphash_match_category = ex.category;
            std::string d = "Imphash matches " + std::to_string(hits) +
                            " known LOLDrivers sample(s)";
            if (!ex.category.empty())
                d += " [" + ex.category + "]";
            add(d, 4);
        }
    }

    if (r.score > 10)
        r.score = 10;
    if (r.score <= 2)
        r.band = "low";
    else if (r.score <= 5)
        r.band = "moderate";
    else if (r.score <= 8)
        r.band = "high";
    else
        r.band = "critical";

    return r;
}

} // namespace drvinspect
