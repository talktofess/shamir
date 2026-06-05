# shamir — threshold secret sharing in C++

[![CI](https://github.com/talktofess/shamir/actions/workflows/ci.yml/badge.svg)](https://github.com/talktofess/shamir/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C%2B%2B-14-00599C.svg)](https://isocpp.org/)
![Tests](https://img.shields.io/badge/tests-13%20passing-brightgreen.svg)

Split a secret into **N shares** such that **any K of them reconstruct it**, but
**any K−1 reveal absolutely nothing** — every possible secret stays equally
likely. This is [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
(Adi Shamir, 1979), the maths behind crypto-wallet seed backups, HSM master-key
splitting, and "3-of-5 board members must agree" key custody.

A pure, dependency-free, unit-tested core over **GF(2⁸)**, plus a terminal demo
you can run.

```
$ ./shamir_demo "attack at dawn" 3 5

  Shamir's Secret Sharing  ·  GF(2^8)
  ----------------------------------------
  secret : "attack at dawn"  (14 bytes)
  scheme : any 3 of 5 shares rebuild it

  shares (distribute these; any one tells you nothing):
     1   01c290b87c820ade5a3aeaa6f399e6
     2   026736d04e750ba12efc048d1cd9e5
     3   03c4d21c53946a5f15b2ce4f8e376d
     4   041a82bb6b5e15ba1b2ff26e888f55
     5   05b9667776bf7444206138ac1a61dd

  recover with 3 shares { 3, 4, 5 } :
    -> "attack at dawn"   [OK]

  with only 2 shares { 1, 4 } (below threshold) :
    -> ".cN..^dOl...9g"   [WRONG]   nothing about the secret leaks
```

## How it works

The whole scheme is one idea: **a polynomial is over-determined by enough points
and totally free with too few.**

1. **Hide the secret as a constant term.** To share one byte `s` with threshold
   `k`, pick a random polynomial of degree `k−1` whose constant term is `s`:
   `f(x) = s + a₁x + a₂x² + … + a_{k-1}x^{k-1}`, with `a₁…a_{k-1}` random.
2. **Shares are points on it.** Share `i` is `(i, f(i))` for `i = 1..n`. The secret
   is `f(0)`, which no share reveals.
3. **k points → one polynomial.** Any `k` shares uniquely determine that degree
   `k−1` polynomial (Lagrange interpolation), so `f(0)` — the secret — comes
   straight back. With only `k−1` points, *every* value of `f(0)` is still
   possible: the missing share could make the constant term anything. That's the
   information-theoretic security — it's not "hard to break", it's *impossible*.
4. **All of it in GF(2⁸).** The arithmetic runs in the 256-element finite field
   AES uses (`gf256`), so every byte is a valid value, there's no rounding, and a
   secret of any length is just shared byte-by-byte (one polynomial per byte,
   evaluated at the same `x` per share).

```
core/
  gf256.{hpp,cpp}   GF(2^8): add=XOR, mul/div/inv via exp/log tables (gen 3, 0x11B)
  shamir.{hpp,cpp}  split() builds the random polynomials; combine() Lagrange-
                    interpolates at x=0 to recover the secret
src/main.cpp        the terminal demo
tests/test_shamir.cpp  the signature deliverable
```

## The signature deliverable: a test suite that proves the guarantee

`combine()` working is table stakes; the interesting part is proving the
*threshold* and that the field maths is exact. The suite (13 tests) covers:

- **the field** — every non-zero element has an inverse (which only holds if the
  generator is primitive), `mul`/`div`/`inv` agree, `a^255 = 1`, distributivity;
- **recovery** — *every* K-subset of the N shares reconstructs the secret
  (all `C(5,3)` of them), and so do larger subsets;
- **the threshold** — fewer than K shares do **not** recover it;
- **edges** — `k=1`, `k=n`, secrets containing `0x00`/`0xFF`, determinism under a
  fixed seed, and rejected bad parameters.

```bash
cmake -B build && cmake --build build
ctest --test-dir build --output-on-failure   # 13/13
./build/shamir_demo                           # the demo above (seeded)
./build/shamir_demo "your secret" 2 4         # custom k-of-n
```

Verified locally with `g++ -std=c++14 -Wall -Wextra` and in CI on every push.

## Honest caveats (please read before trusting it with a real secret)

This is a **correct, educational** implementation — the maths is right and tested
— but it is **not a hardened cryptographic library**:

- **The RNG is not cryptographic.** Coefficients come from a *seedable*
  `std::mt19937_64` (so tests and the demo are reproducible). For a real secret,
  the random coefficients **must** come from a CSPRNG — `mt19937` is predictable.
- **Not constant-time.** The `gf256` table lookups and the Lagrange loop aren't
  written to resist timing/side-channel analysis.
- **No share authentication.** Shares aren't MAC'd, so a tampered share silently
  corrupts the result (this is plain Shamir, not a verifiable/robust variant).

For production use a vetted library (e.g. Daan Sprenkels' `sss`, HashiCorp Vault's
implementation). Use this one to *understand* the scheme.
