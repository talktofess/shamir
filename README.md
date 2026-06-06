# shamir — threshold secret sharing in C++

[![CI](https://github.com/talktofess/shamir/actions/workflows/ci.yml/badge.svg)](https://github.com/talktofess/shamir/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++](https://img.shields.io/badge/C%2B%2B-14-00599C.svg)](https://isocpp.org/)
![Tests](https://img.shields.io/badge/tests-27%20passing-brightgreen.svg)

Split a secret into **N shares** such that **any K of them reconstruct it**, but
**any K−1 reveal absolutely nothing** — every possible secret stays equally
likely. This is [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
(Adi Shamir, 1979), the maths behind crypto-wallet seed backups, HSM master-key
splitting, and "3-of-5 board members must agree" key custody.

A pure, dependency-free, unit-tested core over **GF(2⁸)**, with a **from-scratch
SHA-256** commitment so tampering is detected, an **OS cryptographic RNG**, a
self-describing **share format**, **BIP-39-style word shares** you can write down,
and a `split` / `combine` CLI.

```
$ shamir demo

  Shamir's Secret Sharing  ·  GF(2^8)  +  SHA-256 commitment
  ----------------------------------------------------------
  secret : "attack at dawn"  (14 bytes)
  scheme : any 3 of 5 shares rebuild it

  shares (self-describing; carry k + a commitment to verify):
    SSS1.3.1.c290b87c820ade5a3aeaa6f399e6.d502810c71aeb17e...92aeb90a
    SSS1.3.2.6736d04e750ba12efc048d1cd9e5.d502810c71aeb17e...92aeb90a
    SSS1.3.3.c4d21c53946a5f15b2ce4f8e376d.d502810c71aeb17e...92aeb90a
    SSS1.3.4.1a82bb6b5e15ba1b2ff26e888f55.d502810c71aeb17e...92aeb90a
    SSS1.3.5.b9667776bf7444206138ac1a61dd.d502810c71aeb17e...92aeb90a

  recover with 3 shares { 3, 4, 5 } :
    -> "attack at dawn"   [OK, verified]

  with only 2 shares { 1, 4 } (below threshold) :
    -> ".cN..^dOl...9g"   [WRONG]   nothing about the secret leaks
```

A share string is `SSS1.<k>.<x>.<hex y>.<hex SHA-256 commitment>` — self-contained,
so a holder needs nothing else to reconstruct *and* verify.

### Word shares (write them on paper)

Hex is awful to transcribe, so a share can also be rendered as words from a
built-in 256-word list (one word per byte, plus a 2-word checksum so a wrong or
reordered word is caught):

```
$ shamir split-words "trust no one" 2 4
bi be pin zay hor fad sar so vin lin mub lor nan bay den lo
bi bi rub foo nee vor zoo gon ge bor tad bo kee say tay jin
bi bo moo pa han ru ben tad ro gan he gay li vay zan gu
bi bu tor zar no din for dan za so boo too gad had day va

$ shamir combine-words "bi be pin zay ... lo" "bi bo moo pa ... gu"
secret : "trust no one"
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

**Tamper detection.** A SHA-256 of the secret is carried with the shares as a
public *commitment*. `reconstruct()` checks the recovered secret against it, so a
corrupted or mismatched share set is **rejected**, not silently mis-reconstructed.

```
core/
  gf256.{hpp,cpp}   GF(2^8): add=XOR, mul/div/inv via exp/log tables (gen 3, 0x11B)
  shamir.{hpp,cpp}  split() builds the random polynomials; combine() Lagrange-
                    interpolates at x=0; SeededRng (tests) + SecureRng (OS CSPRNG)
  sha256.{hpp,cpp}  SHA-256 from scratch — the secret commitment
  format.{hpp,cpp}  encode/parse share strings; reconstruct() = combine + verify
  mnemonic.{hpp,cpp}  256-word encoding of a share, with a checksum
src/main.cpp        the split / combine / split-words / combine-words / demo CLI
tests/test_shamir.cpp  the signature deliverable
```

## The signature deliverable: a test suite that proves the guarantee

`combine()` working is table stakes; the interesting part is proving the
*threshold*, that the field maths is exact, and that tampering is caught. The
suite (27 tests) covers:

- **the field** — every non-zero element has an inverse (which only holds if the
  generator is primitive), `mul`/`div`/`inv` agree, `a^255 = 1`, distributivity;
- **recovery** — *every* K-subset of the N shares reconstructs the secret
  (all `C(5,3)` of them), and so do larger subsets;
- **the threshold** — fewer than K shares do **not** recover it;
- **SHA-256** — matches the NIST `""`, `"abc"`, and quick-brown-fox vectors;
- **tamper detection** — `reconstruct()` rejects a corrupted share, shares that
  disagree on the commitment, too few shares, and malformed strings;
- **the secure RNG** — splitting with the OS CSPRNG still round-trips;
- **word shares** — exactly 256 unique words; share→words→share round-trips;
  decoding is case-insensitive; the checksum catches a wrong word; unknown words
  and too-few shares are rejected;
- **edges** — `k=1`, `k=n`, secrets with `0x00`/`0xFF`, determinism, bad params.

```bash
cmake -B build && cmake --build build
ctest --test-dir build --output-on-failure   # 27/27

./build/shamir demo                                  # the walkthrough above
./build/shamir split "correct horse" 3 5             # -> 5 share strings (OS randomness)
./build/shamir combine SSS1.3.2... SSS1.3.4... SSS1.3.5...   # -> secret, verified
./build/shamir split-words "correct horse" 3 5       # -> 5 word-share lines
./build/shamir combine-words "<words>" "<words>" "<words>"  # -> secret
```

Verified locally with `g++ -std=c++14 -Wall -Wextra` and in CI on every push
(CI also runs an end-to-end `split | combine` round-trip).

## Honest caveats (please read before trusting it with a real secret)

This is a **correct, educational** implementation — the maths is right and tested
— but it is **not a hardened cryptographic library**:

- **Real splits use an OS CSPRNG** (`SecureRng`: `/dev/urandom` / `CryptGenRandom`).
  The seedable `mt19937_64` (`SeededRng`) is **only** for reproducible tests and
  the demo — never split a real secret with it.
- **Not constant-time.** The `gf256` table lookups and the Lagrange loop aren't
  written to resist timing/side-channel analysis.
- **Tamper detection ≠ identification.** The commitment tells you the share set is
  wrong; it doesn't pinpoint *which* share, nor does it correct errors (that's
  robust secret sharing, e.g. Rabin–Ben-Or).

For production use a vetted library (e.g. Daan Sprenkels' `sss`, HashiCorp Vault's
implementation). Use this one to *understand* the scheme.
