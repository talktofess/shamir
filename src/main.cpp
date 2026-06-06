#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#include <fcntl.h>
#endif

#include "core/format.hpp"
#include "core/mnemonic.hpp"
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

// ------------------------------------------------------- binary file I/O -----

Bytes readBytes(const std::string& path) {
    std::FILE* f;
    if (path == "-") {
#if defined(_WIN32)
        _setmode(0, _O_BINARY);            // fd 0 = stdin
#endif
        f = stdin;
    } else {
        f = std::fopen(path.c_str(), "rb");
        if (!f) throw std::runtime_error("cannot open " + path);
    }
    Bytes data;
    unsigned char buf[65536];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) data.insert(data.end(), buf, buf + n);
    if (f != stdin) std::fclose(f);
    return data;
}

void writeStdoutBinary(const Bytes& d) {
#if defined(_WIN32)
    _setmode(1, _O_BINARY);                // fd 1 = stdout
#endif
    if (!d.empty()) std::fwrite(d.data(), 1, d.size(), stdout);
}

int cmdSplitFile(const std::string& path, int k, int n) {
    try {
        Bytes secret = readBytes(path);
        if (secret.empty()) { std::fprintf(stderr, "error: empty secret\n"); return 1; }
        shamir::SecureRng rng;
        auto shares = shamir::split(secret, k, n, rng);
        auto commitment = sha256::hash(secret);
        std::printf("# %d-of-%d shares of a %d-byte secret. `shamir combine-file <file>`.\n",
                    k, n, static_cast<int>(secret.size()));
        for (const auto& s : shares) std::printf("%s\n", shamir::encodeShare(s, k, commitment).c_str());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}

int cmdCombineFile(const std::string& path) {
    try {
        std::string text;
        { Bytes b = readBytes(path); text.assign(b.begin(), b.end()); }
        Bytes secret = shamir::reconstructText(text);
        writeStdoutBinary(secret);                 // raw bytes — safe for binary keys
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "could not reconstruct: %s\n", e.what());
        return 1;
    }
}

// ------------------------------------------------------- word (mnemonic) -----

int cmdSplitWords(const std::string& secretStr, int k, int n) {
    const Bytes secret = bytesOf(secretStr);
    try {
        shamir::SecureRng rng;
        auto shares = shamir::split(secret, k, n, rng);
        std::printf("# %d-of-%d word shares. Write each line down; any %d reconstruct\n", k, n, k);
        std::printf("# the secret with `shamir combine-words \"<words>\" ...`.\n");
        for (const auto& s : shares) {
            std::printf("%s\n", shamir::toMnemonic(s, k).c_str());
        }
        return 0;
    } catch (const std::exception& e) {
        std::printf("error: %s\n", e.what());
        return 1;
    }
}

int cmdCombineWords(const std::vector<std::string>& mnemonics) {
    try {
        Bytes secret = shamir::combineMnemonics(mnemonics);
        std::printf("secret : \"%s\"\n", printable(secret).c_str());
        std::printf("hex    : %s\n", hexOf(secret).c_str());
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

    std::printf("\n  share #1 as transcribable words (BIP-39-style, checksummed):\n");
    std::printf("    %s\n\n", shamir::toMnemonic(shares[0], k).c_str());
    return 0;
}

void usage(const char* prog) {
    std::printf("usage:\n");
    std::printf("  %s split \"<secret>\" <k> <n>        split into n shares, threshold k\n", prog);
    std::printf("  %s combine <share> <share> ...     reconstruct + verify from shares\n", prog);
    std::printf("  %s split-file <path|-> <k> <n>     split a binary file/stdin -> share lines\n", prog);
    std::printf("  %s combine-file <path|->           reconstruct -> raw secret on stdout\n", prog);
    std::printf("  %s split-words \"<secret>\" <k> <n>  split into transcribable word shares\n", prog);
    std::printf("  %s combine-words \"<words>\" ...     reconstruct from word shares\n", prog);
    std::printf("  %s demo                             a reproducible walkthrough\n", prog);
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
    if (cmd == "split-file") {
        if (argc < 5) { usage(argv[0]); return 1; }
        return cmdSplitFile(argv[2], std::atoi(argv[3]), std::atoi(argv[4]));
    }
    if (cmd == "combine-file") {
        if (argc < 3) { usage(argv[0]); return 1; }
        return cmdCombineFile(argv[2]);
    }
    if (cmd == "split-words") {
        if (argc < 5) { usage(argv[0]); return 1; }
        return cmdSplitWords(argv[2], std::atoi(argv[3]), std::atoi(argv[4]));
    }
    if (cmd == "combine-words") {
        if (argc < 3) { usage(argv[0]); return 1; }
        return cmdCombineWords(std::vector<std::string>(argv + 2, argv + argc));
    }
    if (cmd == "demo") {
        return cmdDemo();
    }
    usage(argv[0]);
    return 1;
}
