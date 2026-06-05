#include <string>
#include <vector>

#include "core/gf256.hpp"
#include "core/shamir.hpp"
#include "microtest.hpp"

using Bytes = std::vector<std::uint8_t>;

namespace {

Bytes bytes(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

// Pick the shares whose indices are set in `mask`.
std::vector<shamir::Share> subset(const std::vector<shamir::Share>& all, unsigned mask) {
    std::vector<shamir::Share> out;
    for (std::size_t i = 0; i < all.size(); ++i) {
        if (mask & (1u << i)) out.push_back(all[i]);
    }
    return out;
}

int popcount(unsigned m) {
    int c = 0;
    while (m) { c += m & 1; m >>= 1; }
    return c;
}

} // namespace

// --------------------------------------------------------------- GF(2^8) ----

TEST("every non-zero element has a multiplicative inverse") {
    for (int a = 1; a < 256; ++a) {
        CHECK_EQ(gf256::mul(static_cast<std::uint8_t>(a), gf256::inv(static_cast<std::uint8_t>(a))), 1);
    }
}

TEST("field identities: add is XOR, 1 and 0 behave") {
    CHECK_EQ(gf256::add(0xAA, 0x55), 0xFF);
    CHECK_EQ(gf256::mul(0xAB, 1), 0xAB);
    CHECK_EQ(gf256::mul(0xAB, 0), 0);
    CHECK_EQ(gf256::add(0x3C, 0x3C), 0);     // a + a == 0
}

TEST("multiplication distributes over addition") {
    for (int a = 0; a < 256; a += 17) {
        for (int b = 0; b < 256; b += 31) {
            for (int c = 0; c < 256; c += 53) {
                std::uint8_t A = a, B = b, C = c;
                CHECK_EQ(gf256::mul(A, gf256::add(B, C)),
                         gf256::add(gf256::mul(A, B), gf256::mul(A, C)));
            }
        }
    }
}

TEST("div is multiply-by-inverse; pow obeys group order") {
    CHECK_EQ(gf256::div(0xF3, 0x07), gf256::mul(0xF3, gf256::inv(0x07)));
    CHECK_EQ(gf256::pow(0x05, 2), gf256::mul(0x05, 0x05));
    for (int a = 1; a < 256; ++a) {
        CHECK_EQ(gf256::pow(static_cast<std::uint8_t>(a), 255), 1);   // a^255 == 1
    }
}

// --------------------------------------------------------------- Shamir -----

TEST("any K of N shares reconstruct the secret (all subsets)") {
    shamir::Rng rng(12345);
    const Bytes secret = bytes("hello!");
    const int k = 3, n = 5;
    auto shares = shamir::split(secret, k, n, rng);

    int checked = 0;
    for (unsigned mask = 0; mask < (1u << n); ++mask) {
        if (popcount(mask) != k) continue;
        CHECK(shamir::combine(subset(shares, mask)) == secret);
        ++checked;
    }
    CHECK_EQ(checked, 10);   // C(5,3)
}

TEST("more than K shares still reconstruct") {
    shamir::Rng rng(7);
    const Bytes secret = bytes("redundant");
    auto shares = shamir::split(secret, 3, 6, rng);
    CHECK(shamir::combine(shares) == secret);                 // all 6
    CHECK(shamir::combine(subset(shares, 0b001111)) == secret); // 4 of 6
}

TEST("fewer than K shares do NOT recover the secret") {
    shamir::Rng rng(99);
    const Bytes secret = bytes("topsecret");
    const int k = 4, n = 6;
    auto shares = shamir::split(secret, k, n, rng);
    // any k-1 = 3 shares -> wrong answer (deterministic under this seed)
    CHECK(shamir::combine(subset(shares, 0b000111)) != secret);
    CHECK(shamir::combine(subset(shares, 0b101010)) != secret);
}

TEST("k = 1 makes every share equal to the secret") {
    shamir::Rng rng(1);
    const Bytes secret = bytes("AB");
    auto shares = shamir::split(secret, 1, 4, rng);
    for (const auto& s : shares) {
        CHECK(s.y == secret);                                // degree-0 polynomial
        CHECK(shamir::combine({s}) == secret);
    }
}

TEST("k = n works") {
    shamir::Rng rng(2);
    const Bytes secret = bytes("exactly");
    auto shares = shamir::split(secret, 4, 4, rng);
    CHECK(shamir::combine(shares) == secret);
}

TEST("shares use distinct x = 1..n") {
    shamir::Rng rng(3);
    auto shares = shamir::split(bytes("x"), 2, 5, rng);
    for (std::size_t i = 0; i < shares.size(); ++i) {
        CHECK_EQ(shares[i].x, static_cast<int>(i + 1));
    }
}

TEST("handles 0x00 and 0xFF bytes in the secret") {
    shamir::Rng rng(55);
    const Bytes secret = {0x00, 0xFF, 0x00, 0x7F, 0xFF};
    auto shares = shamir::split(secret, 3, 5, rng);
    CHECK(shamir::combine(subset(shares, 0b10110)) == secret);
}

TEST("same seed produces identical shares") {
    shamir::Rng a(42), b(42);
    auto sa = shamir::split(bytes("deterministic"), 3, 5, a);
    auto sb = shamir::split(bytes("deterministic"), 3, 5, b);
    CHECK_EQ(sa.size(), sb.size());
    for (std::size_t i = 0; i < sa.size(); ++i) {
        CHECK_EQ(sa[i].x, sb[i].x);
        CHECK(sa[i].y == sb[i].y);
    }
}

TEST("invalid parameters are rejected") {
    shamir::Rng rng(0);
    bool threw = false;
    try { shamir::split(bytes("x"), 0, 3, rng); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
    threw = false;
    try { shamir::split(bytes("x"), 4, 3, rng); } catch (const std::exception&) { threw = true; }  // k > n
    CHECK(threw);
    threw = false;
    try { shamir::split(Bytes{}, 2, 3, rng); } catch (const std::exception&) { threw = true; }      // empty
    CHECK(threw);
}
