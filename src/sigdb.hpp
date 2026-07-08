#pragma once
#include <string>
#include <unordered_map>

#include "hashing.hpp"

// Loads the flattened LOLDrivers signature database (built by tools/build_db.py)
// and answers "is this exact file a known-abused driver?" by hash lookup --
// the same principle as Microsoft's Vulnerable Driver Blocklist.
namespace drvinspect {

struct SigRecord {
    std::string sha256;
    std::string sha1;
    std::string md5;
    std::string category;    // "vulnerable driver" | "malicious"
    std::string filename;
    std::string publisher;
    std::string loads_despite_hvci;
    std::string imphash;
    bool valid = false;
};

class SignatureDb {
public:
    // Load a TSV produced by tools/build_db.py. Returns false on read error.
    bool load(const std::string& path);

    // Look a file up by its hashes (SHA256, then SHA1, then MD5). Returns an
    // invalid record (valid == false) if nothing matches.
    SigRecord match(const FileHashes& h) const;

    // How many known-bad samples share this imphash, and one example. An
    // imphash match means "same imports in the same order" -- a strong hint of
    // a recompiled variant that a plain file-hash lookup would miss. Returns 0
    // for an empty imphash (never treat "no imports" as a match).
    size_t imphash_hits(const std::string& imphash, SigRecord& example) const;

    size_t size() const { return records_.size(); }

private:
    std::vector<SigRecord> records_;
    std::unordered_map<std::string, size_t> by_sha256_;
    std::unordered_map<std::string, size_t> by_sha1_;
    std::unordered_map<std::string, size_t> by_md5_;
    std::unordered_map<std::string, std::vector<size_t>> by_imphash_;
};

} // namespace drvinspect
