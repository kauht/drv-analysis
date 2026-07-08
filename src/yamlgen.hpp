#pragma once
#include <string>

#include "hashing.hpp"
#include "pe.hpp"

// Emits a draft LOLDrivers YAML entry (schema matching yaml/*.yaml in the
// magicsword-io/LOLDrivers repo) from what drvinspect can extract statically.
// Fields that require parsing the PE VERSIONINFO resource (not yet implemented
// in pe.cpp) or the full X.509 certificate chain (needs ASN.1/PKCS7 parsing,
// out of scope here) are accepted as optional overrides or left as clearly
// marked TODOs -- this is a draft to hand-finish, not a submit-blind output.
namespace drvinspect {

struct YamlOptions {
    std::string category = "vulnerable driver";  // or "malicious"
    std::string author;
    std::string mitre_id = "T1068";
    std::string description;
    std::string company;
    std::string product;
    std::string product_version;
    std::string file_version;
    std::string copyright;
    std::string internal_name;
    std::string original_filename;
    std::string publisher;               // signer name, e.g. from Get-AuthenticodeSignature
    std::vector<std::string> resources;  // extra reference URLs (CVEs, writeups, etc.)
};

// `filename` is the bare driver filename (e.g. "AMDRyzenMasterDriver.sys"), as
// LOLDrivers records it -- not the local extraction path. `data` is the full
// file buffer, needed to compute per-section entropy.
std::string generate_yaml(const std::string& filename, const std::vector<uint8_t>& data,
                          const FileHashes& hashes, const FileHashes& authentihash,
                          const PeInfo& pe, const YamlOptions& opts);

} // namespace drvinspect
