#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// SHA-256 (FIPS 180-4), implemented from scratch. Used here to commit to the
// secret: a public SHA-256 of the secret is carried with the shares, so a
// reconstruction can be checked — a tampered or wrong share set fails the check.
namespace sha256 {

std::array<std::uint8_t, 32> hash(const std::uint8_t* data, std::size_t len);
std::array<std::uint8_t, 32> hash(const std::vector<std::uint8_t>& data);
std::string hex(const std::array<std::uint8_t, 32>& digest);

} // namespace sha256
