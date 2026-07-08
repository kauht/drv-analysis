#pragma once
#include <string>
#include <vector>

#include "pe.hpp"
#include "sigdb.hpp"

// Phase 2: judge an *unknown* driver by what it can do, not by its file hash.
// This is what catches recompiled or brand-new vulnerable drivers that a plain
// hash lookup (Phase 1) misses entirely.
namespace drvinspect {

// The industry-standard "imphash": MD5 over the imported symbols in table
// order. Two drivers built from the same code with the same imports produce
// the same imphash even if a single byte elsewhere changed the file hash.
std::string compute_imphash(const PeInfo& pe);

struct RiskFactor {
    std::string description;
    int points = 0;
};

struct RiskReport {
    std::string imphash;
    int score = 0;              // clamped to 0..10
    std::string band;           // "low" | "moderate" | "high" | "critical"
    std::vector<RiskFactor> factors;
    bool imphash_match = false;         // shares imphash with a known-bad sample
    std::string imphash_match_category; // that sample's category, if matched
};

// Score a driver's BYOVD potential. If `db` is non-null, an imphash match
// against known-bad samples contributes to the score.
RiskReport score_driver(const PeInfo& pe, const SignatureDb* db);

} // namespace drvinspect
