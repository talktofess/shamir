#include "core/mnemonic.hpp"

#include <cctype>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

#include "core/sha256.hpp"

namespace shamir {
namespace {

// 256 short, pronounceable syllables = 16 onsets x 16 rhymes. Deterministic and
// guaranteed unique (a test pins both). Swap in BIP-39 / the PGP word list if you
// prefer — only this table changes.
std::vector<std::string> buildWords() {
    static const char* onset[16] = {"b","d","f","g","k","l","m","n","p","r","s","t","v","z","j","h"};
    static const char* rhyme[16] = {"a","e","i","o","u","ay","ee","oo","ar","or","an","en","in","on","ad","ub"};
    std::vector<std::string> w;
    w.reserve(256);
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j)
            w.push_back(std::string(onset[i]) + rhyme[j]);
    return w;
}

const std::unordered_map<std::string, int>& wordIndex() {
    static const std::unordered_map<std::string, int> m = [] {
        std::unordered_map<std::string, int> x;
        const auto& w = wordlist();
        for (int i = 0; i < static_cast<int>(w.size()); ++i) x[w[i]] = i;
        return x;
    }();
    return m;
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

const std::vector<std::string>& wordlist() {
    static const std::vector<std::string> w = buildWords();
    return w;
}

std::string toMnemonic(const Share& share, int k) {
    std::vector<std::uint8_t> all;
    all.push_back(static_cast<std::uint8_t>(k));
    all.push_back(share.x);
    all.insert(all.end(), share.y.begin(), share.y.end());

    auto digest = sha256::hash(all);
    all.push_back(digest[0]);              // 2-byte checksum -> 2 words
    all.push_back(digest[1]);

    const auto& w = wordlist();
    std::string out;
    for (std::size_t i = 0; i < all.size(); ++i) {
        if (i) out += ' ';
        out += w[all[i]];
    }
    return out;
}

DecodedMnemonic fromMnemonic(const std::string& mnemonic) {
    std::istringstream ss(mnemonic);
    std::string word;
    std::vector<std::uint8_t> bytes;
    const auto& idx = wordIndex();
    while (ss >> word) {
        auto it = idx.find(lower(word));
        if (it == idx.end()) throw std::invalid_argument("unknown word: " + word);
        bytes.push_back(static_cast<std::uint8_t>(it->second));
    }
    if (bytes.size() < 5) throw std::invalid_argument("mnemonic too short");   // k, x, >=1 y, 2 checksum

    std::vector<std::uint8_t> payload(bytes.begin(), bytes.end() - 2);
    auto digest = sha256::hash(payload);
    if (digest[0] != bytes[bytes.size() - 2] || digest[1] != bytes[bytes.size() - 1]) {
        throw std::invalid_argument("checksum failed (a word is wrong or out of order?)");
    }

    DecodedMnemonic d;
    d.k = payload[0];
    d.share.x = payload[1];
    d.share.y.assign(payload.begin() + 2, payload.end());
    return d;
}

std::vector<std::uint8_t> combineMnemonics(const std::vector<std::string>& mnemonics) {
    if (mnemonics.empty()) throw std::invalid_argument("no mnemonics provided");
    std::vector<Share> shares;
    int k = -1;
    for (const std::string& m : mnemonics) {
        DecodedMnemonic d = fromMnemonic(m);
        if (k < 0) k = d.k;
        else if (d.k != k) throw std::invalid_argument("mnemonics disagree on the threshold k");
        shares.push_back(d.share);
    }
    if (static_cast<int>(shares.size()) < k) throw std::invalid_argument("need at least k shares");
    return combine(shares);
}

} // namespace shamir
