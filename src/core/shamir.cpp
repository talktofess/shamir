#include "core/shamir.hpp"

#include <stdexcept>

#include "core/gf256.hpp"

namespace shamir {
namespace {

// Horner evaluation of a polynomial (coeffs low-to-high) at x, in GF(2^8).
std::uint8_t evalPoly(const std::vector<std::uint8_t>& coeffs, std::uint8_t x) {
    std::uint8_t acc = 0;
    for (std::size_t i = coeffs.size(); i-- > 0;) {
        acc = gf256::add(gf256::mul(acc, x), coeffs[i]);
    }
    return acc;
}

// Lagrange interpolation evaluated at x = 0 recovers the constant term (the
// secret byte). In GF(2^8), negation is identity, so (0 - x_m) == x_m and
// (x_j - x_m) == x_j ^ x_m.
std::uint8_t interpolateAtZero(const std::vector<Share>& shares, std::size_t byteIndex) {
    std::uint8_t secret = 0;
    for (std::size_t j = 0; j < shares.size(); ++j) {
        std::uint8_t num = 1, den = 1;
        const std::uint8_t xj = shares[j].x;
        for (std::size_t m = 0; m < shares.size(); ++m) {
            if (m == j) continue;
            const std::uint8_t xm = shares[m].x;
            num = gf256::mul(num, xm);
            den = gf256::mul(den, gf256::add(xj, xm));
        }
        const std::uint8_t basis = gf256::mul(num, gf256::inv(den));
        secret = gf256::add(secret, gf256::mul(shares[j].y[byteIndex], basis));
    }
    return secret;
}

} // namespace

std::vector<Share> split(const std::vector<std::uint8_t>& secret, int k, int n, ByteSource& rng) {
    if (k < 1 || n < 1 || k > n || n > 255) {
        throw std::invalid_argument("require 1 <= k <= n <= 255");
    }
    if (secret.empty()) {
        throw std::invalid_argument("secret must be non-empty");
    }

    std::vector<Share> shares(static_cast<std::size_t>(n));
    for (int s = 0; s < n; ++s) {
        shares[s].x = static_cast<std::uint8_t>(s + 1);
        shares[s].y.resize(secret.size());
    }

    std::vector<std::uint8_t> coeffs(static_cast<std::size_t>(k));
    for (std::size_t b = 0; b < secret.size(); ++b) {
        coeffs[0] = secret[b];                       // the secret hides as the constant term
        for (int c = 1; c < k; ++c) coeffs[c] = rng.byte();
        for (int s = 0; s < n; ++s) {
            shares[s].y[b] = evalPoly(coeffs, shares[s].x);
        }
    }
    return shares;
}

std::vector<std::uint8_t> combine(const std::vector<Share>& shares) {
    if (shares.empty()) throw std::invalid_argument("no shares provided");
    const std::size_t len = shares[0].y.size();
    for (const auto& s : shares) {
        if (s.x == 0) throw std::invalid_argument("share x must be non-zero");
        if (s.y.size() != len) throw std::invalid_argument("inconsistent share length");
    }
    for (std::size_t i = 0; i < shares.size(); ++i) {
        for (std::size_t j = i + 1; j < shares.size(); ++j) {
            if (shares[i].x == shares[j].x) throw std::invalid_argument("duplicate share x");
        }
    }

    std::vector<std::uint8_t> secret(len);
    for (std::size_t b = 0; b < len; ++b) {
        secret[b] = interpolateAtZero(shares, b);
    }
    return secret;
}

} // namespace shamir
