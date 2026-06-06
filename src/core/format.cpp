#include "core/format.hpp"

#include <stdexcept>

#include "core/sha256.hpp"

namespace shamir {
namespace {

const char* HEX = "0123456789abcdef";

std::string hexBytes(const std::uint8_t* p, std::size_t n) {
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s += HEX[p[i] >> 4];
        s += HEX[p[i] & 0xF];
    }
    return s;
}

int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::uint8_t> fromHex(const std::string& s) {
    if (s.empty() || (s.size() % 2) != 0) throw std::invalid_argument("bad hex length");
    std::vector<std::uint8_t> out(s.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        int hi = hexVal(s[i * 2]);
        int lo = hexVal(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("bad hex digit");
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::vector<std::string> splitDots(const std::string& s) {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : s) {
        if (c == '.') { parts.push_back(cur); cur.clear(); }
        else cur += c;
    }
    parts.push_back(cur);
    return parts;
}

int parsePositiveInt(const std::string& s) {
    if (s.empty()) throw std::invalid_argument("expected a number");
    for (char c : s) if (c < '0' || c > '9') throw std::invalid_argument("expected a number");
    return std::stoi(s);
}

} // namespace

std::string encodeShare(const Share& share, int k, const std::array<std::uint8_t, 32>& commitment) {
    std::string out = "SSS1.";
    out += std::to_string(k);
    out += ".";
    out += std::to_string(static_cast<int>(share.x));
    out += ".";
    out += hexBytes(share.y.data(), share.y.size());
    out += ".";
    out += hexBytes(commitment.data(), commitment.size());
    return out;
}

ParsedShare parseShare(const std::string& text) {
    std::vector<std::string> p = splitDots(text);
    if (p.size() != 5 || p[0] != "SSS1") throw std::invalid_argument("not an SSS1 share");

    ParsedShare out;
    out.k = parsePositiveInt(p[1]);
    int x = parsePositiveInt(p[2]);
    if (x < 1 || x > 255) throw std::invalid_argument("share x out of range");
    out.share.x = static_cast<std::uint8_t>(x);
    out.share.y = fromHex(p[3]);

    std::vector<std::uint8_t> commit = fromHex(p[4]);
    if (commit.size() != 32) throw std::invalid_argument("commitment must be 32 bytes");
    for (int i = 0; i < 32; ++i) out.commitment[i] = commit[i];
    return out;
}

std::vector<std::uint8_t> reconstruct(const std::vector<std::string>& shareStrings) {
    if (shareStrings.empty()) throw std::invalid_argument("no shares provided");

    std::vector<ParsedShare> parsed;
    parsed.reserve(shareStrings.size());
    for (const std::string& s : shareStrings) parsed.push_back(parseShare(s));

    const int k = parsed[0].k;
    const std::array<std::uint8_t, 32> commitment = parsed[0].commitment;

    std::vector<Share> shares;
    for (const ParsedShare& p : parsed) {
        if (p.k != k) throw std::invalid_argument("shares disagree on the threshold k");
        if (p.commitment != commitment) {
            throw std::invalid_argument("shares disagree on the commitment (tampering?)");
        }
        shares.push_back(p.share);
    }
    if (static_cast<int>(shares.size()) < k) {
        throw std::invalid_argument("need at least k shares to reconstruct");
    }

    std::vector<std::uint8_t> secret = combine(shares);
    if (sha256::hash(secret) != commitment) {
        throw std::invalid_argument("verification failed: reconstructed secret does not match "
                                    "the commitment (tampered or incorrect shares)");
    }
    return secret;
}

std::vector<std::uint8_t> reconstructText(const std::string& text) {
    std::vector<std::string> shares;
    std::string line;
    auto flush = [&]() {
        std::size_t a = line.find_first_not_of(" \t\r");
        if (a != std::string::npos) {
            std::size_t b = line.find_last_not_of(" \t\r");
            std::string t = line.substr(a, b - a + 1);
            if (!t.empty() && t[0] != '#') shares.push_back(t);
        }
        line.clear();
    };
    for (char c : text) {
        if (c == '\n') flush();
        else line += c;
    }
    flush();

    if (shares.empty()) throw std::invalid_argument("no share lines found");
    return reconstruct(shares);
}

} // namespace shamir
