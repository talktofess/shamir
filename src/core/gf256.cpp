#include "core/gf256.hpp"

namespace gf256 {
namespace {

// exp/log tables built once around the generator 3 (a primitive element of the
// field). exp is doubled to 512 entries so mul can index log[a]+log[b] (up to
// 508) without a modulo.
struct Tables {
    std::uint8_t exp[512];
    std::uint8_t log[256];

    Tables() {
        std::uint8_t x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = x;
            log[x] = static_cast<std::uint8_t>(i);
            // x *= 3  ==  (x*2) ^ x, with x*2 reduced by 0x11B when it overflows.
            std::uint8_t hi = x & 0x80;
            std::uint8_t dbl = static_cast<std::uint8_t>(x << 1);
            if (hi) dbl ^= 0x1B;
            x = static_cast<std::uint8_t>(dbl ^ x);
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
        log[0] = 0;   // undefined; never read for a == 0
    }
};

const Tables& tables() {
    static const Tables t;
    return t;
}

} // namespace

std::uint8_t mul(std::uint8_t a, std::uint8_t b) {
    if (a == 0 || b == 0) return 0;
    const Tables& t = tables();
    return t.exp[t.log[a] + t.log[b]];
}

std::uint8_t inv(std::uint8_t a) {
    const Tables& t = tables();
    return t.exp[255 - t.log[a]];           // a^(254) = a^(-1)
}

std::uint8_t div(std::uint8_t a, std::uint8_t b) {
    if (a == 0) return 0;
    const Tables& t = tables();
    return t.exp[t.log[a] + 255 - t.log[b]];
}

std::uint8_t pow(std::uint8_t a, int e) {
    e %= 255;
    if (e < 0) e += 255;
    std::uint8_t result = 1, base = a;
    while (e) {
        if (e & 1) result = mul(result, base);
        base = mul(base, base);
        e >>= 1;
    }
    return result;
}

} // namespace gf256
