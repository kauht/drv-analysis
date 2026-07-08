#include "sigdb.hpp"

#include <fstream>
#include <sstream>

namespace drvinspect {
namespace {

// Split a line on tabs into exactly `n` fields (missing trailing fields become
// empty strings, so a short row never reads past the vector).
std::vector<std::string> split_tsv(const std::string& line, size_t n) {
    std::vector<std::string> out(n);
    size_t start = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t tab = line.find('\t', start);
        if (tab == std::string::npos) {
            out[i] = line.substr(start);
            break;
        }
        out[i] = line.substr(start, tab - start);
        start = tab + 1;
    }
    return out;
}

} // namespace

bool SignatureDb::load(const std::string& path) {
    std::ifstream f(path);
    if (!f)
        return false;

    std::string line;
    bool header = true;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (header) {  // first line is the column header
            header = false;
            continue;
        }
        if (line.empty())
            continue;

        auto c = split_tsv(line, 8);
        SigRecord r;
        r.sha256 = c[0];
        r.sha1 = c[1];
        r.md5 = c[2];
        r.category = c[3];
        r.filename = c[4];
        r.publisher = c[5];
        r.loads_despite_hvci = c[6];
        r.imphash = c[7];
        r.valid = true;

        size_t idx = records_.size();
        records_.push_back(std::move(r));
        const SigRecord& ref = records_[idx];
        if (!ref.sha256.empty())  by_sha256_[ref.sha256] = idx;
        if (!ref.sha1.empty())    by_sha1_[ref.sha1] = idx;
        if (!ref.md5.empty())     by_md5_[ref.md5] = idx;
        if (!ref.imphash.empty()) by_imphash_[ref.imphash].push_back(idx);
    }
    return true;
}

SigRecord SignatureDb::match(const FileHashes& h) const {
    // Prefer the strongest hash. SHA1/MD5 remain useful for entries whose
    // SHA256 the catalog never recorded.
    if (auto it = by_sha256_.find(h.sha256); it != by_sha256_.end())
        return records_[it->second];
    if (auto it = by_sha1_.find(h.sha1); it != by_sha1_.end())
        return records_[it->second];
    if (auto it = by_md5_.find(h.md5); it != by_md5_.end())
        return records_[it->second];
    return SigRecord{};  // valid == false
}

size_t SignatureDb::imphash_hits(const std::string& imphash,
                                 SigRecord& example) const {
    if (imphash.empty())
        return 0;
    auto it = by_imphash_.find(imphash);
    if (it == by_imphash_.end() || it->second.empty())
        return 0;
    example = records_[it->second.front()];
    return it->second.size();
}

} // namespace drvinspect
