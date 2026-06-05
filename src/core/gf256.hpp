#pragma once
#include <cstdint>

// Arithmetic in GF(2^8) — the same 256-element finite field AES uses, with the
// reducing polynomial x^8 + x^4 + x^3 + x + 1 (0x11B). Every byte is an element;
// addition is XOR and multiplication is polynomial multiply-mod, done in O(1) via
// precomputed exp/log tables. This is the field Shamir's scheme runs over so that
// any byte value is a valid coordinate and the maths stays exact (no rounding).
namespace gf256 {

inline std::uint8_t add(std::uint8_t a, std::uint8_t b) { return a ^ b; }   // and subtract
std::uint8_t mul(std::uint8_t a, std::uint8_t b);
std::uint8_t div(std::uint8_t a, std::uint8_t b);   // b != 0
std::uint8_t inv(std::uint8_t a);                   // a != 0
std::uint8_t pow(std::uint8_t a, int e);

} // namespace gf256
