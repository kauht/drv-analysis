#include "hashing.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <stdexcept>

namespace drvinspect {
namespace {

// Turn raw digest bytes into a lowercase hex string.
std::string to_hex(const std::vector<uint8_t>& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

// One [offset, length) byte range within a buffer to feed into a hash.
struct ByteRange {
    size_t offset;
    size_t length;
};

// Hash the concatenation of several byte ranges of `data` with the named CNG
// algorithm. Used both for a plain whole-file hash (one range) and for the
// Authentihash (several disjoint ranges, skipping the checksum/signature).
std::string hash_ranges(const wchar_t* algorithm, const std::vector<uint8_t>& data,
                        const std::vector<ByteRange>& ranges) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, 0) != 0)
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    DWORD hash_len = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                      reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0);

    BCRYPT_HASH_HANDLE handle = nullptr;
    BCryptCreateHash(alg, &handle, nullptr, 0, nullptr, 0, 0);

    for (const auto& r : ranges) {
        size_t off = r.offset < data.size() ? r.offset : data.size();
        size_t len = r.length;
        if (off + len > data.size())
            len = data.size() - off;
        if (len == 0)
            continue;
        // BCryptHashData takes a non-const buffer, but does not modify it.
        BCryptHashData(handle, const_cast<PUCHAR>(data.data() + off),
                       static_cast<ULONG>(len), 0);
    }

    std::vector<uint8_t> digest(hash_len);
    BCryptFinishHash(handle, digest.data(), hash_len, 0);

    BCryptDestroyHash(handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    return to_hex(digest);
}

std::string hash_with(const wchar_t* algorithm, const std::vector<uint8_t>& data) {
    return hash_ranges(algorithm, data, {{0, data.size()}});
}

} // namespace

std::string md5_hex(const std::string& s) {
    std::vector<uint8_t> bytes(s.begin(), s.end());
    return hash_with(BCRYPT_MD5_ALGORITHM, bytes);
}

FileHashes compute_hashes(const std::vector<uint8_t>& data) {
    FileHashes h;
    h.md5    = hash_with(BCRYPT_MD5_ALGORITHM, data);
    h.sha1   = hash_with(BCRYPT_SHA1_ALGORITHM, data);
    h.sha256 = hash_with(BCRYPT_SHA256_ALGORITHM, data);
    return h;
}

FileHashes compute_authentihash(const std::vector<uint8_t>& data, const PeInfo& pe) {
    std::vector<ByteRange> ranges;

    // [0, CheckSum) -- skip the 4-byte checksum field itself.
    ranges.push_back({0, pe.checksum_file_offset});
    size_t after_checksum = pe.checksum_file_offset + 4;

    // [after CheckSum, security directory entry) -- skip that 8-byte entry.
    ranges.push_back({after_checksum, pe.security_dir_file_offset - after_checksum});
    size_t after_secdir = pe.security_dir_file_offset + 8;

    // [after security dir entry, end of unsigned data). If the file already
    // carries a signature (security_dir_size > 0), stop before it -- that
    // trailing certificate blob is never part of what gets signed. Otherwise
    // hash to the actual end of file.
    size_t end = (pe.security_dir_size > 0 && pe.security_dir_file_start > 0)
                     ? pe.security_dir_file_start
                     : data.size();
    if (end > after_secdir)
        ranges.push_back({after_secdir, end - after_secdir});

    FileHashes h;
    h.md5    = hash_ranges(BCRYPT_MD5_ALGORITHM, data, ranges);
    h.sha1   = hash_ranges(BCRYPT_SHA1_ALGORITHM, data, ranges);
    h.sha256 = hash_ranges(BCRYPT_SHA256_ALGORITHM, data, ranges);
    return h;
}

} // namespace drvinspect
