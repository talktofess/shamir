#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include "core/format.hpp"
#include "core/sha256.hpp"
#include "core/shamir.hpp"

namespace {

using Bytes = std::vector<std::uint8_t>;

Bytes bytesOf(const std::string& s) { return Bytes(s.begin(), s.end()); }

std::string hexOf(const Bytes& b) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (std::uint8_t v : b) { s += H[v >> 4]; s += H[v & 0xF]; }
    return s;
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

// ------------------------------------------------------------------ split ----

int cmdSplit(const std::string& secretStr, int k, int n) {
    const Bytes secret = bytesOf(secretStr);
    try {
        shamir::SecureRng rng;                       // OS entropy — real randomness
        auto shares = shamir::split(secret, k, n, rng);
        auto commitment = sha256::hash(secret);

        std::printf("# %d-of-%d shares for a %d-byte secret. Keep them apart;\n",
                    k, n, static_cast<int>(secret.size()));
        std::printf("# any %d reconstruct it with `shamir combine <share> ...`.\n", k);
        for (const auto& s : shares) {
            std::printf("%s\n", shamir::encodeShare(s, k, commitment).c_str());
        }
        return 0;
    } catch (const std::exception& e) {
        std::printf("error: %s\n", e.what());
        return 1;
    }
}

// ---------------------------------------------------------------- combine ----

int cmdCombine(const std::vector<std::string>& shareStrings) {
    try {
        Bytes secret = shamir::reconstruct(shareStrings);
        std::printf("secret : \"%s\"\n", printable(secret).c_str());
        std::printf("hex    : %s\n", hexOf(secret).c_str());
        std::printf("status : verified against the commitment\n");
        return 0;
    } catch (const std::exception& e) {
        std::printf("could not reconstruct: %s\n", e.what());
        return 1;
    }
}

// ------------------------------------------------------------------- demo ----

std::vector<shamir::Share> pick(const std::vector<shamir::Share>& all, int count,
                                std::mt19937_64& eng, std::vector<int>& xsOut) {
    std::vector<int> idx(all.size());
    std::iota(idx.begin(), idx.end(), 0);
    std::shuffle(idx.begin(), idx.end(), eng);
    idx.resize(count);
    std::sort(idx.begin(), idx.end());

    std::vector<shamir::Share> out;
    xsOut.clear();
    for (int i : idx) { out.push_back(all[i]); xsOut.push_back(all[i].x); }
    return out;
}

int cmdDemo() {
    const Bytes secret = bytesOf("attack at dawn");
    const int k = 3, n = 5;
    shamir::SeededRng rng(0xC0FFEEu);

    std::printf("\n  Shamir's Secret Sharing  ·  GF(2^8)  +  SHA-256 commitment\n");
    std::printf("  ----------------------------------------------------------\n");
    std::printf("  secret : \"%s\"  (%d bytes)\n", printable(secret).c_str(), (int) secret.size());
    std::printf("  scheme : any %d of %d shares rebuild it\n\n", k, n);

    auto shares = shamir::split(secret, k, n, rng);
    auto commitment = sha256::hash(secret);

    std::printf("  shares (self-describing; carry k + a commitment to verify):\n");
    for (const auto& s : shares) {
        std::printf("    %s\n", shamir::encodeShare(s, k, commitment).c_str());
    }

    std::vector<int> okXs;
    auto enough = pick(shares, k, rng.eng, okXs);
    std::printf("\n  recover with %d shares %s :\n", k, braces(okXs).c_str());
    std::printf("    -> \"%s\"   [OK, verified]\n", printable(shamir::combine(enough)).c_str());

    std::vector<int> fewXs;
    auto tooFew = pick(shares, k - 1, rng.eng, fewXs);
    std::printf("\n  with only %d shares %s (below threshold) :\n", k - 1, braces(fewXs).c_str());
    std::printf("    -> \"%s\"   [WRONG]   nothing about the secret leaks\n",
                printable(shamir::combine(tooFew)).c_str());
    std::printf("\n");
    return 0;
}

void usage(const char* prog) {
    std::printf("usage:\n");
    std::printf("  %s split \"<secret>\" <k> <n>     split into n shares, threshold k\n", prog);
    std::printf("  %s combine <share> <share> ...  reconstruct + verify from shares\n", prog);
    std::printf("  %s demo                          a reproducible walkthrough\n", prog);
}

} // namespace

int main(int argc, char** argv) {
    const std::string cmd = argc > 1 ? argv[1] : "demo";

    if (cmd == "split") {
        if (argc < 5) { usage(argv[0]); return 1; }
        return cmdSplit(argv[2], std::atoi(argv[3]), std::atoi(argv[4]));
    }
    if (cmd == "combine") {
        if (argc < 3) { usage(argv[0]); return 1; }
        return cmdCombine(std::vector<std::string>(argv + 2, argv + argc));
    }
    if (cmd == "demo") {
        return cmdDemo();
    }
    usage(argv[0]);
    return 1;
}
