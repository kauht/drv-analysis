#include "disasm.hpp"

#include <Zydis/Zydis.h>

#include <unordered_map>
#include <unordered_set>

namespace drvinspect {
namespace {

// _DRIVER_OBJECT layout (x64): the MajorFunction[] table starts at offset 0x70,
// each entry an 8-byte pointer. IRP_MJ_DEVICE_CONTROL is index 0x0E, so a store
// to [DriverObject + 0xE0] installs the IOCTL dispatch routine.
constexpr int64_t kMajorBase = 0x70;
constexpr int64_t kPtr = 8;
constexpr int kMaxMajor = 0x1b;
constexpr int kDeviceControlIndex = 0x0e;

// Kernel primitives whose presence *inside the reachable handler* is what
// distinguishes a vulnerable driver from one that merely imports them.
const std::unordered_set<std::string>& primitive_apis() {
    static const std::unordered_set<std::string> s = {
        "MmMapIoSpace", "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache",
        "MmGetPhysicalAddress", "MmCopyMemory", "ZwMapViewOfSection",
        "__readmsr", "__writemsr", "ZwTerminateProcess", "ZwOpenProcess",
        "PsLookupProcessByProcessId", "ZwProtectVirtualMemory",
        "KeStackAttachProcess", "memmove", "memcpy",
    };
    return s;
}

std::string bare_name(const std::string& dll_bang_name) {
    auto p = dll_bang_name.find('!');
    return p == std::string::npos ? dll_bang_name : dll_bang_name.substr(p + 1);
}

// Maps RVAs to a pointer into the file image + how many bytes remain in that
// section, so we can hand Zydis a bounded buffer.
class ImageView {
public:
    ImageView(const std::vector<uint8_t>& data, const PeInfo& pe)
        : data_(data), pe_(pe) {}

    const uint8_t* ptr(uint32_t rva, size_t& avail) const {
        for (const auto& s : pe_.sections) {
            if (rva >= s.virtual_address &&
                rva < s.virtual_address + s.raw_size) {
                uint32_t delta = rva - s.virtual_address;
                size_t off = static_cast<size_t>(s.raw_pointer) + delta;
                if (off >= data_.size())
                    return nullptr;
                avail = data_.size() - off;
                size_t sec_avail = s.raw_size - delta;
                if (avail > sec_avail)
                    avail = sec_avail;
                return data_.data() + off;
            }
        }
        return nullptr;
    }

    bool is_exec(uint32_t rva) const {
        for (const auto& s : pe_.sections)
            if (rva >= s.virtual_address &&
                rva < s.virtual_address + s.virtual_size)
                return (s.characteristics & 0x20000000) != 0;  // MEM_EXECUTE
        return false;
    }

private:
    const std::vector<uint8_t>& data_;
    const PeInfo& pe_;
};

ZydisRegister norm(ZydisRegister r) {
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r);
}

// Scan every executable section for `mov [base + majoroffset], reg` where `reg`
// was just loaded via `lea reg, [rip + handler]`. Records the DEVICE_CONTROL
// handler RVA. Also notes whether IoCreateDeviceSecure is imported (a properly
// ACL'd device is much less likely to be trivially exploitable).
void locate_dispatch(const ZydisDecoder& dec, const ImageView& view,
                     const PeInfo& pe, DispatchAnalysis& out) {
    for (const auto& sec : pe.sections) {
        if (!(sec.characteristics & 0x20000000))  // MEM_EXECUTE
            continue;
        size_t avail = 0;
        const uint8_t* base = view.ptr(sec.virtual_address, avail);
        if (!base)
            continue;

        std::unordered_map<ZydisRegister, uint32_t> lea_targets;
        uint32_t rva = sec.virtual_address;
        size_t off = 0;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

        while (off < avail &&
               ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, base + off, avail - off,
                                                   &insn, ops))) {
            uint64_t runtime = pe.image_base + rva;

            if (insn.mnemonic == ZYDIS_MNEMONIC_LEA &&
                insn.operand_count_visible >= 2 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                ops[1].mem.base == ZYDIS_REGISTER_RIP) {
                uint64_t abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[1],
                                                          runtime, &abs))) {
                    uint32_t target = static_cast<uint32_t>(abs - pe.image_base);
                    if (view.is_exec(target))
                        lea_targets[norm(ops[0].reg.value)] = target;
                    else
                        lea_targets.erase(norm(ops[0].reg.value));
                }
            } else if (insn.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       insn.operand_count_visible >= 2 &&
                       ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ops[0].mem.base != ZYDIS_REGISTER_RIP &&
                       ops[0].mem.base != ZYDIS_REGISTER_NONE &&
                       ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                int64_t disp = ops[0].mem.disp.value;
                if (disp >= kMajorBase &&
                    disp <= kMajorBase + kMaxMajor * kPtr &&
                    (disp - kMajorBase) % kPtr == 0) {
                    int major = static_cast<int>((disp - kMajorBase) / kPtr);
                    auto it = lea_targets.find(norm(ops[1].reg.value));
                    if (it != lea_targets.end() &&
                        major == kDeviceControlIndex) {
                        out.found_dispatch = true;
                        out.device_control_rva = it->second;
                    }
                }
                // A plain register write invalidates any tracked lea value.
                if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                    lea_targets.erase(norm(ops[0].reg.value));
            } else if (insn.operand_count_visible >= 1 &&
                       ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                lea_targets.erase(norm(ops[0].reg.value));
            }

            off += insn.length;
            rva += insn.length;
        }
    }
}

// Does an immediate look like an IOCTL control code (CTL_CODE layout)?
// Device type sits in the high 16 bits. We accept FILE_DEVICE_UNKNOWN (0x22,
// overwhelmingly the most common for vulnerable drivers) and the custom range
// 0x8000-0xBFFF, but NOT 0xC000+/0x4000+ -- those collide with NTSTATUS/HRESULT
// constants (e.g. STATUS_* like 0xC00000BB) whose low bits are also 3.
bool looks_like_ioctl(uint32_t imm) {
    uint32_t dt = imm >> 16;
    return dt == 0x0022 || (dt >= 0x8000 && dt <= 0xBFFF);
}

// Explore the dispatch handler as a bounded call-graph (not just linearly):
// the real work lives in the sub-handlers the dispatcher `call`s. Collect
// imported primitive calls anywhere in that graph, and IOCTL codes / method
// bits from mov/sub/add/cmp immediates (compilers lower the IOCTL switch to a
// subtract + jump table, so the codes are not always `cmp` operands).
void analyze_handler(const ZydisDecoder& dec, const ImageView& view,
                     const PeInfo& pe, DispatchAnalysis& out) {
    std::unordered_map<uint32_t, std::string> iat;
    for (const auto& t : pe.iat_targets)
        iat[t.first] = t.second;

    std::unordered_set<std::string> seen_calls;
    std::unordered_set<uint32_t> seen_codes;
    std::unordered_set<uint32_t> visited;
    std::vector<uint32_t> worklist = {out.device_control_rva};

    int func_budget = 128;       // distinct functions to explore
    int total_budget = 20000;    // total instructions across the graph

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];

    while (!worklist.empty() && func_budget-- > 0 && total_budget > 0) {
        uint32_t func = worklist.back();
        worklist.pop_back();
        if (!visited.insert(func).second)
            continue;

        size_t avail = 0;
        const uint8_t* base = view.ptr(func, avail);
        if (!base)
            continue;
        if (avail > 4096)
            avail = 4096;  // bound per-function decode

        uint32_t rva = func;
        size_t off = 0;
        int per_func = 1500;
        while (off < avail && per_func-- > 0 && total_budget-- > 0 &&
               ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, base + off, avail - off,
                                                   &insn, ops))) {
            uint64_t runtime = pe.image_base + rva;
            bool is_call = insn.mnemonic == ZYDIS_MNEMONIC_CALL;
            bool is_jmp = insn.mnemonic == ZYDIS_MNEMONIC_JMP;

            if ((is_call || is_jmp) && insn.operand_count_visible >= 1 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                ops[0].mem.base == ZYDIS_REGISTER_RIP) {
                // call/jmp [rip+x] -> imported API via the IAT slot.
                uint64_t abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0],
                                                          runtime, &abs))) {
                    uint32_t slot = static_cast<uint32_t>(abs - pe.image_base);
                    auto it = iat.find(slot);
                    if (it != iat.end()) {
                        std::string bn = bare_name(it->second);
                        if (primitive_apis().count(bn) && !seen_calls.count(bn)) {
                            seen_calls.insert(bn);
                            out.primitive_calls.push_back(it->second);
                        }
                    }
                }
            } else if ((is_call || is_jmp) && insn.operand_count_visible >= 1 &&
                       ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                // Direct call/jmp rel -> follow into the target function.
                uint64_t abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0],
                                                          runtime, &abs))) {
                    uint32_t tgt = static_cast<uint32_t>(abs - pe.image_base);
                    if (view.is_exec(tgt) && !visited.count(tgt))
                        worklist.push_back(tgt);
                }
            }

            // IOCTL codes: mov/sub/add/cmp with an IOCTL-looking immediate.
            if (insn.mnemonic == ZYDIS_MNEMONIC_MOV ||
                insn.mnemonic == ZYDIS_MNEMONIC_SUB ||
                insn.mnemonic == ZYDIS_MNEMONIC_ADD ||
                insn.mnemonic == ZYDIS_MNEMONIC_CMP) {
                for (int i = 0; i < insn.operand_count_visible; ++i) {
                    if (ops[i].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        continue;
                    uint32_t imm = static_cast<uint32_t>(ops[i].imm.value.u);
                    if (!looks_like_ioctl(imm))
                        continue;
                    if (seen_codes.insert(imm).second)
                        out.ioctl_codes.push_back(imm);
                    if ((imm & 3) == 3)  // METHOD_NEITHER
                        out.method_neither = true;
                }
            }

            if (insn.mnemonic == ZYDIS_MNEMONIC_RET)
                break;  // end of this function's linear block
            off += insn.length;
            rva += insn.length;
        }
    }
}

} // namespace

DispatchAnalysis analyze_dispatch(const std::vector<uint8_t>& data,
                                  const PeInfo& pe) {
    DispatchAnalysis out;
    if (!pe.is_64bit)  // x64 only for this first cut
        return out;

    ZydisDecoder dec;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64,
                                       ZYDIS_STACK_WIDTH_64)))
        return out;
    out.supported = true;

    // Whether the device is opened with a restrictive ACL is a property of
    // DriverEntry (where IoCreateDevice[Secure] is called), not of the
    // DEVICE_CONTROL handler -- check the import table directly rather than
    // depend on which function in the call graph happens to reference it.
    for (const auto& sym : pe.imports) {
        if (sym.by_ordinal)
            continue;
        if (sym.name == "IoCreateDeviceSecure" ||
            sym.name == "WdmlibIoCreateDeviceSecure") {
            out.secure_device = true;
            break;
        }
    }

    ImageView view(data, pe);
    locate_dispatch(dec, view, pe, out);
    if (out.found_dispatch)
        analyze_handler(dec, view, pe, out);
    return out;
}

} // namespace drvinspect
