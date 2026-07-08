#include "pe.hpp"

#include <windows.h>

#include <cstddef>
#include <cstring>

namespace drvinspect {
namespace {

// Safe typed read at a byte offset: returns nullptr if [off, off+sizeof(T))
// would run past the end of the buffer. Every structure access goes through
// this so a malformed/truncated driver can't make us read out of bounds.
template <typename T>
const T* at(const std::vector<uint8_t>& data, size_t off) {
    if (off > data.size() || sizeof(T) > data.size() - off)
        return nullptr;
    return reinterpret_cast<const T*>(data.data() + off);
}

// Read a NUL-terminated ASCII string starting at a file offset, bounded.
std::string read_cstr(const std::vector<uint8_t>& data, size_t off) {
    std::string s;
    while (off < data.size() && data[off] != 0) {
        s.push_back(static_cast<char>(data[off]));
        ++off;
    }
    return s;
}

// Translate a Relative Virtual Address to a file offset using the section map.
// Returns SIZE_MAX if the RVA falls outside every section's raw data.
size_t rva_to_offset(const std::vector<SectionInfo>& sections, uint32_t rva) {
    for (const auto& s : sections) {
        uint32_t span = s.raw_size > s.virtual_size ? s.raw_size : s.virtual_size;
        if (rva >= s.virtual_address && rva < s.virtual_address + span) {
            uint32_t delta = rva - s.virtual_address;
            if (delta < s.raw_size)
                return static_cast<size_t>(s.raw_pointer) + delta;
        }
    }
    return SIZE_MAX;
}

// Walk the import directory and collect every imported symbol. `thunk_size`
// and the ordinal-flag differ between 32- and 64-bit images, so the two
// architectures share this template.
template <typename ThunkType, ThunkType OrdinalFlag>
void parse_imports(const std::vector<uint8_t>& data, PeInfo& info,
                   uint32_t import_dir_rva) {
    size_t desc_off = rva_to_offset(info.sections, import_dir_rva);
    if (desc_off == SIZE_MAX)
        return;

    for (;; desc_off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        const auto* desc = at<IMAGE_IMPORT_DESCRIPTOR>(data, desc_off);
        if (!desc || desc->Name == 0)
            break;

        size_t name_off = rva_to_offset(info.sections, desc->Name);
        if (name_off == SIZE_MAX)
            continue;
        std::string dll = read_cstr(data, name_off);

        // Prefer the Import Lookup Table (OriginalFirstThunk); fall back to the
        // IAT (FirstThunk) for images where the ILT was stripped. Either way,
        // the resolved pointers live in FirstThunk -- that's the IAT slot RVA
        // a `call [rip+x]` will reference, so we track it per symbol.
        uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                       : desc->FirstThunk;
        uint32_t iat_rva = desc->FirstThunk;
        size_t thunk_off = rva_to_offset(info.sections, thunk_rva);
        if (thunk_off == SIZE_MAX)
            continue;

        for (uint32_t idx = 0;; ++idx, thunk_off += sizeof(ThunkType)) {
            const auto* thunk = at<ThunkType>(data, thunk_off);
            if (!thunk || *thunk == 0)
                break;

            ImportedSymbol sym;
            sym.dll = dll;
            if (*thunk & OrdinalFlag) {
                sym.by_ordinal = true;
                sym.ordinal = static_cast<uint16_t>(*thunk & 0xFFFF);
            } else {
                size_t ibn_off = rva_to_offset(
                    info.sections, static_cast<uint32_t>(*thunk));
                if (ibn_off == SIZE_MAX)
                    continue;
                // IMAGE_IMPORT_BY_NAME = 2-byte Hint followed by the name.
                sym.name = read_cstr(data, ibn_off + 2);
                uint32_t slot = iat_rva +
                    idx * static_cast<uint32_t>(sizeof(ThunkType));
                info.iat_targets.push_back({slot, dll + "!" + sym.name});
            }
            info.imports.push_back(std::move(sym));
        }
    }
}

} // namespace

std::optional<PeInfo> parse_pe(const std::vector<uint8_t>& data) {
    const auto* dos = at<IMAGE_DOS_HEADER>(data, 0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
        return std::nullopt;

    size_t nt_off = static_cast<size_t>(dos->e_lfanew);
    const auto* sig = at<DWORD>(data, nt_off);
    if (!sig || *sig != IMAGE_NT_SIGNATURE)
        return std::nullopt;

    const auto* file_hdr =
        at<IMAGE_FILE_HEADER>(data, nt_off + sizeof(DWORD));
    if (!file_hdr)
        return std::nullopt;

    PeInfo info;
    info.machine = file_hdr->Machine;
    info.timestamp = file_hdr->TimeDateStamp;
    info.characteristics = file_hdr->Characteristics;

    size_t opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const auto* magic = at<WORD>(data, opt_off);
    if (!magic)
        return std::nullopt;
    info.is_64bit = (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // Grab subsystem + the import data directory from the optional header.
    uint32_t import_dir_rva = 0;
    if (info.is_64bit) {
        const auto* opt = at<IMAGE_OPTIONAL_HEADER64>(data, opt_off);
        if (!opt)
            return std::nullopt;
        info.subsystem = opt->Subsystem;
        info.entry_point = opt->AddressOfEntryPoint;
        info.image_base = opt->ImageBase;
        import_dir_rva =
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        info.checksum_file_offset = opt_off + offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
        info.security_dir_file_offset = opt_off +
            offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY);
        info.security_dir_file_start = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        info.security_dir_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    } else {
        const auto* opt = at<IMAGE_OPTIONAL_HEADER32>(data, opt_off);
        if (!opt)
            return std::nullopt;
        info.subsystem = opt->Subsystem;
        info.entry_point = opt->AddressOfEntryPoint;
        info.image_base = opt->ImageBase;
        import_dir_rva =
            opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        info.checksum_file_offset = opt_off + offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum);
        info.security_dir_file_offset = opt_off +
            offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY);
        info.security_dir_file_start = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        info.security_dir_size = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    }

    // Section headers follow the optional header.
    size_t sec_off = opt_off + file_hdr->SizeOfOptionalHeader;
    for (uint16_t i = 0; i < file_hdr->NumberOfSections; ++i) {
        const auto* sh = at<IMAGE_SECTION_HEADER>(
            data, sec_off + i * sizeof(IMAGE_SECTION_HEADER));
        if (!sh)
            break;
        SectionInfo s;
        char name[9] = {0};
        std::memcpy(name, sh->Name, 8);
        s.name = name;
        s.virtual_address = sh->VirtualAddress;
        s.virtual_size = sh->Misc.VirtualSize;
        s.raw_pointer = sh->PointerToRawData;
        s.raw_size = sh->SizeOfRawData;
        s.characteristics = sh->Characteristics;
        info.sections.push_back(std::move(s));
    }

    if (import_dir_rva != 0) {
        if (info.is_64bit)
            parse_imports<uint64_t, IMAGE_ORDINAL_FLAG64>(data, info,
                                                          import_dir_rva);
        else
            parse_imports<uint32_t, IMAGE_ORDINAL_FLAG32>(data, info,
                                                          import_dir_rva);
    }

    return info;
}

} // namespace drvinspect
