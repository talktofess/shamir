#pragma once
#include <cstdint>
#include <random>
#include <vector>

// Shamir's Secret Sharing.
//
// Split a secret into n "shares" so that any k of them reconstruct it exactly,
// while any k-1 reveal *nothing* — every possible secret remains equally likely.
// The trick: hide the secret as the constant term of a random degree-(k-1)
// polynomial over GF(2^8); each share is the polynomial evaluated at a distinct
// x. k points determine a degree-(k-1) polynomial uniquely (so the secret is
// recoverable); k-1 points leave the constant term completely free.
//
// Each byte of the secret gets its own independent polynomial, evaluated at the
// same x per share, so arbitrary-length secrets work.
namespace shamir {

// Where the polynomial coefficients come from.
struct ByteSource {
    virtual std::uint8_t byte() = 0;
    virtual ~ByteSource() = default;
};

// Deterministic, seedable — for reproducible tests and the demo. NOT secure.
struct SeededRng : ByteSource {
    std::mt19937_64 eng;
    explicit SeededRng(std::uint64_t seed) : eng(seed) {}
    std::uint8_t byte() override { return static_cast<std::uint8_t>(eng() & 0xFF); }
};

// OS cryptographic RNG (/dev/urandom on POSIX, rand_s on Windows) — for real use.
class SecureRng : public ByteSource {
public:
    SecureRng();
    ~SecureRng() override;
    std::uint8_t byte() override;
private:
    void refill();
    unsigned char buf_[64];
    std::size_t pos_ = sizeof(buf_);
    void* handle_ = nullptr;        // FILE* on POSIX; unused on Windows
};

struct Share {
    std::uint8_t x;                 // the evaluation point (1..n), distinct & non-zero
    std::vector<std::uint8_t> y;    // one polynomial value per secret byte
};

// Split `secret` into `n` shares with threshold `k`. Requires 1 <= k <= n <= 255
// and a non-empty secret.
std::vector<Share> split(const std::vector<std::uint8_t>& secret, int k, int n, ByteSource& rng);

// Reconstruct the secret from >= k shares (with distinct x's). Fewer than k
// shares will "succeed" but yield the wrong secret — that's the point.
std::vector<std::uint8_t> combine(const std::vector<Share>& shares);

} // namespace shamir
