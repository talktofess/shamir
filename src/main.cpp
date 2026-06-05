#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include "core/shamir.hpp"

namespace {

using Bytes = std::vector<std::uint8_t>;

std::string hexOf(const Bytes& b) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (std::uint8_t v : b) {
        s += H[v >> 4];
        s += H[v & 0xF];
    }
    return s;
}

std::string shareHex(const shamir::Share& s) {
    Bytes packed;
    packed.push_back(s.x);
    packed.insert(packed.end(), s.y.begin(), s.y.end());
    return hexOf(packed);
}

std::string printable(const Bytes& b) {
    std::string s;
    for (std::uint8_t v : b) s += (v >= 32 && v < 127) ? static_cast<char>(v) : '.';
    return s;
}

std::string braces(const std::vector<int>& xs) {
    std::string s = "{ ";
    for (std::size_t i = 0; i < xs.size(); ++i) {
        s += std::to_string(xs[i]);
        if (i + 1 < xs.size()) s += ", ";
    }
    return s + " }";
}

// Pick `count` distinct shares at random; returns the chosen shares and their x's.
std::vector<shamir::Share> pick(const std::vector<shamir::Share>& all, int count,
                                shamir::Rng& rng, std::vector<int>& xsOut) {
    std::vector<int> idx(all.size());
    std::iota(idx.begin(), idx.end(), 0);
    std::shuffle(idx.begin(), idx.end(), rng.eng);
    idx.resize(count);
    std::sort(idx.begin(), idx.end());

    std::vector<shamir::Share> out;
    xsOut.clear();
    for (int i : idx) {
        out.push_back(all[i]);
        xsOut.push_back(all[i].x);
    }
    return out;
}

void run(const Bytes& secret, int k, int n, std::uint64_t seed) {
    shamir::Rng rng(seed);

    std::printf("\n  Shamir's Secret Sharing  ·  GF(2^8)\n");
    std::printf("  ----------------------------------------\n");
    std::printf("  secret : \"%s\"  (%d bytes)\n", printable(secret).c_str(), (int) secret.size());
    std::printf("  scheme : any %d of %d shares rebuild it\n\n", k, n);

    auto shares = shamir::split(secret, k, n, rng);

    std::printf("  shares (distribute these; any one tells you nothing):\n");
    for (const auto& s : shares) {
        std::printf("    %2d   %s\n", s.x, shareHex(s).c_str());
    }

    std::vector<int> okXs;
    auto enough = pick(shares, k, rng, okXs);
    std::printf("\n  recover with %d shares %s :\n", k, braces(okXs).c_str());
    std::printf("    -> \"%s\"   [OK]\n", printable(shamir::combine(enough)).c_str());

    if (k > 1) {
        std::vector<int> fewXs;
        auto tooFew = pick(shares, k - 1, rng, fewXs);
        std::printf("\n  with only %d shares %s (below threshold) :\n", k - 1, braces(fewXs).c_str());
        std::printf("    -> \"%s\"   [WRONG]   nothing about the secret leaks\n",
                    printable(shamir::combine(tooFew)).c_str());
    }
    std::printf("\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc >= 4) {
        const std::string secret = argv[1];
        const int k = std::atoi(argv[2]);
        const int n = std::atoi(argv[3]);
        std::random_device rd;
        try {
            run(Bytes(secret.begin(), secret.end()), k, n,
                (static_cast<std::uint64_t>(rd()) << 32) ^ rd());
        } catch (const std::exception& e) {
            std::printf("error: %s\n", e.what());
            return 1;
        }
        return 0;
    }

    if (argc > 1) {
        std::printf("usage: %s \"<secret>\" <k> <n>     (k of n threshold)\n", argv[0]);
        return 1;
    }

    // No args: a reproducible demo (also the CI smoke test).
    const std::string s = "attack at dawn";
    run(Bytes(s.begin(), s.end()), 3, 5, 0xC0FFEEu);
    return 0;
}
