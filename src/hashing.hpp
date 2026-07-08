#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "pe.hpp"

// LOLDrivers keys every entry on file hashes. We compute the three the
// dataset uses (MD5, SHA1, SHA256) via the Windows CNG / BCrypt API.
namespace drvinspect {

struct FileHashes {
    std::string md5;
    std::string sha1;
    std::string sha256;
};

// Compute all three hashes over a buffer. Returns lowercase hex strings.
FileHashes compute_hashes(const std::vector<uint8_t>& data);

// MD5 of an arbitrary string, lowercase hex. Used to build the imphash.
std::string md5_hex(const std::string& s);

// The "Authentihash": the hash Authenticode actually signs, per Microsoft's
// "Windows Authenticode Portable Executable Signature Format" spec. Unlike a
// plain file hash it excludes the PE checksum field, the certificate-table
// directory entry, and any already-appended signature bytes -- so it stays
// constant whether or not (or how) the file is signed. LOLDrivers records
// this as MD5/SHA1/SHA256, matching FileHashes' shape.
FileHashes compute_authentihash(const std::vector<uint8_t>& data, const PeInfo& pe);

} // namespace drvinspect
