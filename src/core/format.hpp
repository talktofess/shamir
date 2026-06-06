#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "core/shamir.hpp"

// A self-describing text format for a share, so each one carries everything a
// holder needs to reconstruct *and verify*: the threshold k, the point x, the
// share bytes, and a SHA-256 commitment to the secret.
//
//   SSS1.<k>.<x>.<hex y bytes>.<hex 32-byte commitment>
//
// reconstruct() combines >= k shares and checks the result against the
// commitment, so a tampered or mismatched share set is detected rather than
// silently returning the wrong secret.
namespace shamir {

std::string encodeShare(const Share& share, int k, const std::array<std::uint8_t, 32>& commitment);

struct ParsedShare {
    int k;
    Share share;
    std::array<std::uint8_t, 32> commitment;
};

ParsedShare parseShare(const std::string& text);   // throws std::invalid_argument if malformed

// Reconstruct the secret from share strings (>= k of them), verifying the
// commitment. Throws std::invalid_argument on inconsistent k/commitment, too few
// shares, or a failed verification (tampering / wrong shares).
std::vector<std::uint8_t> reconstruct(const std::vector<std::string>& shareStrings);

// Reconstruct from a block of text with one share per line; blank lines and lines
// starting with '#' are ignored (so the output of `split` pipes straight in).
std::vector<std::uint8_t> reconstructText(const std::string& text);

} // namespace shamir
