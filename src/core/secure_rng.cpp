// OS-backed cryptographic RNG for SecureRng. Deliberately uses direct OS entropy
// rather than std::random_device, which is non-cryptographic (and historically
// even deterministic) on some toolchains.
#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h>
#include <stdexcept>

#include "core/shamir.hpp"

namespace shamir {

SecureRng::SecureRng() {
    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        throw std::runtime_error("CryptAcquireContext failed");
    }
    handle_ = reinterpret_cast<void*>(prov);
}

SecureRng::~SecureRng() {
    if (handle_) CryptReleaseContext(reinterpret_cast<HCRYPTPROV>(handle_), 0);
}

void SecureRng::refill() {
    HCRYPTPROV prov = reinterpret_cast<HCRYPTPROV>(handle_);
    if (!CryptGenRandom(prov, static_cast<DWORD>(sizeof(buf_)), buf_)) {
        throw std::runtime_error("CryptGenRandom failed");
    }
    pos_ = 0;
}

} // namespace shamir

#else   // POSIX

#include <cstdio>
#include <stdexcept>

#include "core/shamir.hpp"

namespace shamir {

SecureRng::SecureRng() {
    handle_ = std::fopen("/dev/urandom", "rb");
    if (!handle_) throw std::runtime_error("cannot open /dev/urandom");
}

SecureRng::~SecureRng() {
    if (handle_) std::fclose(static_cast<std::FILE*>(handle_));
}

void SecureRng::refill() {
    std::FILE* f = static_cast<std::FILE*>(handle_);
    if (std::fread(buf_, 1, sizeof(buf_), f) != sizeof(buf_)) {
        throw std::runtime_error("/dev/urandom read failed");
    }
    pos_ = 0;
}

} // namespace shamir

#endif

namespace shamir {

std::uint8_t SecureRng::byte() {
    if (pos_ >= sizeof(buf_)) refill();
    return buf_[pos_++];
}

} // namespace shamir
