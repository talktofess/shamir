#include <string>
#include <vector>

#include <set>

#include "core/format.hpp"
#include "core/gf256.hpp"
#include "core/mnemonic.hpp"
#include "core/sha256.hpp"
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
    shamir::SeededRng rng(12345);
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
    shamir::SeededRng rng(7);
    const Bytes secret = bytes("redundant");
    auto shares = shamir::split(secret, 3, 6, rng);
    CHECK(shamir::combine(shares) == secret);                 // all 6
    CHECK(shamir::combine(subset(shares, 0b001111)) == secret); // 4 of 6
}

TEST("fewer than K shares do NOT recover the secret") {
    shamir::SeededRng rng(99);
    const Bytes secret = bytes("topsecret");
    const int k = 4, n = 6;
    auto shares = shamir::split(secret, k, n, rng);
    // any k-1 = 3 shares -> wrong answer (deterministic under this seed)
    CHECK(shamir::combine(subset(shares, 0b000111)) != secret);
    CHECK(shamir::combine(subset(shares, 0b101010)) != secret);
}

TEST("k = 1 makes every share equal to the secret") {
    shamir::SeededRng rng(1);
    const Bytes secret = bytes("AB");
    auto shares = shamir::split(secret, 1, 4, rng);
    for (const auto& s : shares) {
        CHECK(s.y == secret);                                // degree-0 polynomial
        CHECK(shamir::combine({s}) == secret);
    }
}

TEST("k = n works") {
    shamir::SeededRng rng(2);
    const Bytes secret = bytes("exactly");
    auto shares = shamir::split(secret, 4, 4, rng);
    CHECK(shamir::combine(shares) == secret);
}

TEST("shares use distinct x = 1..n") {
    shamir::SeededRng rng(3);
    auto shares = shamir::split(bytes("x"), 2, 5, rng);
    for (std::size_t i = 0; i < shares.size(); ++i) {
        CHECK_EQ(shares[i].x, static_cast<int>(i + 1));
    }
}

TEST("handles 0x00 and 0xFF bytes in the secret") {
    shamir::SeededRng rng(55);
    const Bytes secret = {0x00, 0xFF, 0x00, 0x7F, 0xFF};
    auto shares = shamir::split(secret, 3, 5, rng);
    CHECK(shamir::combine(subset(shares, 0b10110)) == secret);
}

TEST("same seed produces identical shares") {
    shamir::SeededRng a(42), b(42);
    auto sa = shamir::split(bytes("deterministic"), 3, 5, a);
    auto sb = shamir::split(bytes("deterministic"), 3, 5, b);
    CHECK_EQ(sa.size(), sb.size());
    for (std::size_t i = 0; i < sa.size(); ++i) {
        CHECK_EQ(sa[i].x, sb[i].x);
        CHECK(sa[i].y == sb[i].y);
    }
}

TEST("invalid parameters are rejected") {
    shamir::SeededRng rng(0);
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

// --------------------------------------------------------------- SHA-256 ----

TEST("sha-256 matches known test vectors") {
    CHECK_EQ(sha256::hex(sha256::hash(bytes(""))),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256::hex(sha256::hash(bytes("abc"))),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(sha256::hex(sha256::hash(bytes("The quick brown fox jumps over the lazy dog"))),
             std::string("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"));
}

// --------------------------------------------------------------- SecureRng --

TEST("split with the OS secure RNG still reconstructs") {
    shamir::SecureRng rng;
    const Bytes secret = bytes("from OS entropy");
    auto shares = shamir::split(secret, 3, 5, rng);
    CHECK(shamir::combine(subset(shares, 0b10101)) == secret);   // shares 0,2,4
}

// --------------------------------------------------------------- format -----

TEST("share string round-trips through encode/parse") {
    shamir::SeededRng rng(7);
    const Bytes secret = bytes("format me");
    auto shares = shamir::split(secret, 3, 5, rng);
    auto commit = sha256::hash(secret);

    shamir::ParsedShare p = shamir::parseShare(shamir::encodeShare(shares[1], 3, commit));
    CHECK_EQ(p.k, 3);
    CHECK_EQ(static_cast<int>(p.share.x), static_cast<int>(shares[1].x));
    CHECK(p.share.y == shares[1].y);
    CHECK(p.commitment == commit);
}

TEST("reconstruct recovers and verifies the commitment") {
    shamir::SeededRng rng(8);
    const Bytes secret = bytes("verify me please");
    auto shares = shamir::split(secret, 3, 5, rng);
    auto commit = sha256::hash(secret);

    std::vector<std::string> strs;
    for (int i : {0, 2, 4}) strs.push_back(shamir::encodeShare(shares[i], 3, commit));
    CHECK(shamir::reconstruct(strs) == secret);
}

TEST("reconstruct detects a tampered share") {
    shamir::SeededRng rng(9);
    const Bytes secret = bytes("dont touch this");
    auto shares = shamir::split(secret, 3, 5, rng);
    auto commit = sha256::hash(secret);

    auto tampered = shares[0];
    tampered.y[0] ^= 0xFF;                       // corrupt the share bytes, keep the commitment
    std::vector<std::string> strs = {
        shamir::encodeShare(tampered, 3, commit),
        shamir::encodeShare(shares[1], 3, commit),
        shamir::encodeShare(shares[2], 3, commit),
    };
    bool threw = false;
    try { shamir::reconstruct(strs); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

TEST("reconstruct rejects shares that disagree on the commitment") {
    shamir::SeededRng rng(10);
    auto shares = shamir::split(bytes("abcd"), 2, 4, rng);
    auto good = sha256::hash(bytes("abcd"));
    auto other = sha256::hash(bytes("evil"));
    std::vector<std::string> strs = {
        shamir::encodeShare(shares[0], 2, good),
        shamir::encodeShare(shares[1], 2, other),
    };
    bool threw = false;
    try { shamir::reconstruct(strs); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

TEST("reconstruct rejects too few shares") {
    shamir::SeededRng rng(11);
    const Bytes secret = bytes("need three");
    auto shares = shamir::split(secret, 3, 5, rng);
    auto commit = sha256::hash(secret);
    std::vector<std::string> strs = {
        shamir::encodeShare(shares[0], 3, commit),
        shamir::encodeShare(shares[1], 3, commit),   // only 2 < k=3
    };
    bool threw = false;
    try { shamir::reconstruct(strs); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

TEST("parseShare rejects malformed input") {
    bool threw = false;
    try { shamir::parseShare("garbage"); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
    threw = false;
    try { shamir::parseShare("SSS1.3.1.zz.00"); } catch (const std::exception&) { threw = true; }  // bad hex
    CHECK(threw);
}

// --------------------------------------------------------------- mnemonic ---

TEST("the wordlist has exactly 256 unique words") {
    const auto& w = shamir::wordlist();
    CHECK_EQ(w.size(), 256);
    std::set<std::string> uniq(w.begin(), w.end());
    CHECK_EQ(uniq.size(), 256);
}

TEST("a share round-trips through words") {
    shamir::SeededRng rng(20);
    auto shares = shamir::split(bytes("word me"), 3, 5, rng);  // 7-byte secret
    std::string m = shamir::toMnemonic(shares[2], 3);

    // word count == k-byte + x-byte + y + 2 checksum
    std::size_t words = 1;
    for (char c : m) if (c == ' ') ++words;
    CHECK_EQ(words, 2 + 7 + 2);

    auto d = shamir::fromMnemonic(m);
    CHECK_EQ(d.k, 3);
    CHECK_EQ(static_cast<int>(d.share.x), static_cast<int>(shares[2].x));
    CHECK(d.share.y == shares[2].y);
}

TEST("mnemonic decoding is case-insensitive") {
    shamir::SeededRng rng(21);
    auto shares = shamir::split(bytes("CASE"), 2, 3, rng);
    std::string m = shamir::toMnemonic(shares[0], 2);
    std::string upper = m;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    auto d = shamir::fromMnemonic(upper);
    CHECK(d.share.y == shares[0].y);
}

TEST("the checksum catches a wrong word") {
    shamir::SeededRng rng(22);
    auto shares = shamir::split(bytes("guard"), 2, 3, rng);
    std::string m = shamir::toMnemonic(shares[0], 2);
    // replace the first word with a different valid word
    std::string firstWord = m.substr(0, m.find(' '));
    const std::string& w0 = shamir::wordlist()[0];
    const std::string& w1 = shamir::wordlist()[1];
    std::string swapped = (firstWord == w0 ? w1 : w0) + m.substr(m.find(' '));
    bool threw = false;
    try { shamir::fromMnemonic(swapped); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

TEST("unknown words are rejected") {
    bool threw = false;
    try { shamir::fromMnemonic("ba be notaword bo bu"); } catch (const std::exception&) { threw = true; }
    CHECK(threw);
}

TEST("split -> mnemonics -> combine recovers the secret") {
    shamir::SeededRng rng(23);
    const Bytes secret = bytes("words as backup");
    auto shares = shamir::split(secret, 3, 5, rng);
    std::vector<std::string> mns;
    for (int i : {1, 2, 4}) mns.push_back(shamir::toMnemonic(shares[i], 3));   // 3 of 5
    CHECK(shamir::combineMnemonics(mns) == secret);
}
