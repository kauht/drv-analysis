#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Minimal PE (Portable Executable) parser, focused on the fields that matter
// when triaging a Windows driver: architecture, timestamp, sections, and the
// imported kernel APIs that hint at what the driver can do.
namespace drvinspect {

struct SectionInfo {
    std::string name;
    uint32_t virtual_address = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_pointer = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0;
};

struct ImportedSymbol {
    std::string dll;   // e.g. "ntoskrnl.exe"
    std::string name;  // e.g. "MmMapIoSpace" (empty if imported by ordinal)
    uint16_t ordinal = 0;
    bool by_ordinal = false;
};

struct PeInfo {
    bool is_64bit = false;
    uint16_t machine = 0;
    uint32_t timestamp = 0;        // PE TimeDateStamp (unix epoch seconds)
    uint16_t characteristics = 0;
    uint16_t subsystem = 0;        // IMAGE_SUBSYSTEM_* (1 == native/driver)
    uint32_t entry_point = 0;      // AddressOfEntryPoint (RVA of DriverEntry)
    uint64_t image_base = 0;       // preferred load address
    // Raw file offsets needed to compute the Authenticode hash (which must
    // exclude the checksum field and the certificate-table directory entry).
    size_t checksum_file_offset = 0;
    size_t security_dir_file_offset = 0;  // offset of the 8-byte IMAGE_DIRECTORY_ENTRY_SECURITY
    // DataDirectory[SECURITY].VirtualAddress is a special case in the PE spec:
    // for this one directory entry the field holds a FILE OFFSET, not an RVA.
    uint32_t security_dir_file_start = 0;
    uint32_t security_dir_size = 0;       // DataDirectory[SECURITY].Size (0 if unsigned)
    std::vector<SectionInfo> sections;
    std::vector<ImportedSymbol> imports;
    // The address of an imported function's IAT slot -> "dll!name". Lets the
    // disassembler resolve `call [rip+x]` targets back to the API name.
    std::vector<std::pair<uint32_t, std::string>> iat_targets;
};

// Parse an in-memory PE image. Returns nullopt if the buffer is not a valid PE.
std::optional<PeInfo> parse_pe(const std::vector<uint8_t>& data);

} // namespace drvinspect
