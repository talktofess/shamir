#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "core/shamir.hpp"

// BIP-39-style word encoding for shares: turn a share's bytes into a sequence of
// short words a human can write down or read aloud, instead of a hex blob. We use
// a built-in 256-word list so each byte maps to exactly one word (no bit-packing),
// and append a 2-byte SHA-256 checksum (two words) so a mis-transcribed or
// reordered word is caught on decode.
//
// A mnemonic encodes [k][x][y...] + checksum, so it is a self-contained backup of
// one share. (It does not carry the secret-level commitment that the SSS1 string
// format does — its job is human transcription with error detection.)
namespace shamir {

const std::vector<std::string>& wordlist();   // exactly 256 unique words

std::string toMnemonic(const Share& share, int k);

struct DecodedMnemonic {
    int k;
    Share share;
};

// Decode a space-separated mnemonic (case-insensitive). Throws std::invalid_argument
// on an unknown word or a failed checksum.
DecodedMnemonic fromMnemonic(const std::string& mnemonic);

// Decode >= k mnemonics and reconstruct the secret.
std::vector<std::uint8_t> combineMnemonics(const std::vector<std::string>& mnemonics);

} // namespace shamir
