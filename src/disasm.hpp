#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "pe.hpp"

// Phase 3 (deep): light disassembly of a driver's dispatch path. Finds the
// IRP_MJ_DEVICE_CONTROL handler and inspects it for the two things that turn a
// dangerous *capability* into an actual BYOVD *vulnerability*: a kernel
// primitive reachable from the handler, and METHOD_NEITHER IOCTLs (raw,
// unvalidated user pointers). Requires Zydis; x64 only for now.
namespace drvinspect {

struct DispatchAnalysis {
    bool supported = false;         // false for non-x64 / no code section
    bool found_dispatch = false;    // located the DEVICE_CONTROL handler
    uint32_t device_control_rva = 0;

    std::vector<std::string> primitive_calls;  // e.g. "ntoskrnl.exe!MmMapIoSpace"
    std::vector<uint32_t> ioctl_codes;          // IOCTL constants seen in the handler
    bool method_neither = false;                // any METHOD_NEITHER IOCTL
    bool secure_device = false;                 // used IoCreateDeviceSecure
};

// Analyse the dispatch routine. `data` is the full PE image, `pe` its parse.
DispatchAnalysis analyze_dispatch(const std::vector<uint8_t>& data,
                                  const PeInfo& pe);

} // namespace drvinspect
