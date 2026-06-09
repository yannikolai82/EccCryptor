# CEccModule

A small, self-contained C++ class that wraps Elliptic Curve Cryptography
(NIST P-256) so a caller can do four things with a uniform `char*`-only,
hex-string API:

1. Generate a fresh public/private keypair.
2. Encrypt a plaintext under a public key (hybrid ECIES).
3. Decrypt that ciphertext with the matching private key.
4. Sign data with the private key and verify the signature with the public key.

The implementation links against OpenSSL (1.0.2 .. 3.x), compiles unchanged on
Windows (MSVC or MinGW-w64) and Linux/macOS, and is shipped with the OpenSSL
headers and runtime DLLs vendored under [`third_party/`](third_party/) so it
can be built and run on a machine **with no internet access**.

---

## Contents

- [Cryptographic design](#cryptographic-design)
- [String formats (everything is hex)](#string-formats-everything-is-hex)
- [Files in this project](#files-in-this-project)
- [Public API](#public-api)
- [Return codes](#return-codes)
- [Buffer sizes](#buffer-sizes)
- [Quick start example](#quick-start-example)
- [Pluggable RNG](#pluggable-rng)
- [Building](#building)
  - [Windows, offline (vendored OpenSSL)](#windows-offline-vendored-openssl)
  - [Linux / macOS (system OpenSSL)](#linux--macos-system-openssl)
  - [MSVC + vcpkg](#msvc--vcpkg)
- [Vendored third-party files](#vendored-third-party-files)
- [Cross-platform notes](#cross-platform-notes)
- [Security notes & limitations](#security-notes--limitations)

---

## Cryptographic design

| Concern                | Choice                                              |
|------------------------|-----------------------------------------------------|
| Elliptic curve         | **NIST P-256** (`secp256r1`, `prime256v1`)          |
| Key encapsulation      | **ECIES**: ephemeral ECDH → HKDF-SHA256 → AES key   |
| Symmetric cipher       | **AES-256-GCM** (confidentiality **and** integrity) |
| Signature scheme       | **ECDSA-SHA256**, raw `r‖s` encoding (64 bytes)     |
| Public key encoding    | Uncompressed point `04‖X‖Y` (65 bytes)              |
| Private key encoding   | Raw scalar `d` (32 bytes)                           |
| Random number source   | Pluggable via [`IEccRng`](CEccModule.h) interface;<br>default is OpenSSL `RAND_bytes` |

### Why P-256 instead of a homemade curve?

Strength of an elliptic curve does **not** come from keeping the curve
coefficients secret — it comes from decades of public cryptanalysis. A random
homemade curve typically has small subgroup order, anomalous structure, or
other weaknesses that allow attacks vastly faster than brute force. Computing
the group order `n` correctly (needed for valid private keys) requires
Schoof's algorithm and is easy to get wrong. P-256 is the widely-vetted
default; this module uses it.

### Why ECIES + AES-GCM?

Plain ECC can only encrypt a single curve point worth of data. To encrypt
arbitrary-length messages we use the standard hybrid construction:

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  Encrypt(pubKey, plaintext):                                    │
  │   1. (r, R) = fresh ephemeral keypair on P-256                  │
  │   2. S      = ECDH(r, pubKey)              [shared secret]      │
  │   3. K      = HKDF-SHA256(S, info="CEccModule-ECIES-v1")        │
  │   4. iv     = 12 random bytes                                   │
  │   5. (ct, tag) = AES-256-GCM(K, iv, plaintext)                  │
  │   6. ciphertext-blob = R ‖ iv ‖ tag ‖ ct                        │
  └─────────────────────────────────────────────────────────────────┘
```

Decryption recomputes `S = ECDH(privKey, R)` (mathematically identical to
step 2 above) and runs GCM in reverse. AES-GCM's authentication tag detects
any tampering of the ciphertext.

---

## String formats (everything is hex)

Every `char*` parameter — keys, plaintext, ciphertext, signatures — is a
**null-terminated, uppercase hexadecimal string**. This keeps the API
binary-safe (no embedded NULs, no charset surprises) and trivially
loggable/serializable.

If your application has raw bytes or ordinary text, hex-encode them before
calling `EncrptData`/`SignData` and hex-decode the result of `DecrptData`.
See [`main.cpp`](main.cpp) for the two-line helpers `StrToHex` / `HexToStr`.

### Sizes (fixed for P-256, in hex chars)

| Value           | Bytes | Hex chars |
|-----------------|-------|-----------|
| Public key      | 65    | **130**   |
| Private key     | 32    | **64**    |
| Signature       | 64    | **128**   |
| Ciphertext      | 93 + N | **186 + 2·N**  (N = plaintext-byte length) |

(Buffers must hold those chars plus one byte for the `\0` terminator. The
header defines macros `ECC_PUBKEY_HEX_LEN = 131`, `ECC_PRIKEY_HEX_LEN = 65`,
`ECC_SIGN_HEX_LEN = 129`, `ECC_ENC_OVERHEAD_HEX = 187`.)

---

## Files in this project

```
KGH/
├── CEccModule.h            Public class + IEccRng interface + return codes
├── CEccModule.cpp          Implementation (OpenSSL EVP / EC / ECDSA)
├── main.cpp                Demo program: keygen, encrypt, decrypt, sign,
│                           verify, tamper tests, custom RNG sanity check
├── Makefile                Cross-platform build (Linux/macOS/MinGW)
├── build.bat               Windows offline build using vendored OpenSSL
├── README.md               This file
└── third_party/
    └── openssl/
        ├── include/openssl/*.h    142 OpenSSL 3.x headers
        ├── lib/libcrypto.a        Static libcrypto
        ├── lib/libcrypto.dll.a    Import library for dynamic link
        └── bin/
            ├── libcrypto-3-x64.dll        Runtime DLL (dynamic link)
            └── libwinpthread-1.dll        MinGW pthreads runtime
```

---

## Public API

```cpp
class CEccModule
{
public:
    CEccModule();
    ~CEccModule();

    // Replace the RNG used for keygen, ephemerals, and AES-GCM IVs.
    // Pass nullptr to revert to the default OpenSSL CSPRNG.
    void SetRng(IEccRng* pRng);

    // pchPubKey: out, >= ECC_PUBKEY_HEX_LEN bytes (131)
    // pchPriKey: out, >= ECC_PRIKEY_HEX_LEN bytes (65)
    int GetKey(char* pchPubKey, char* pchPriKey);

    // pchPubKey: in  hex public key
    // pchPlain : in  hex plaintext (your data, hex-encoded)
    // pchEnc   : out hex ciphertext;
    //            >= ECC_ENC_OVERHEAD_HEX + strlen(pchPlain) bytes
    int EncrptData(char* pchPubKey, char* pchPlain, char* pchEnc);

    // pchPriKey: in  hex private key
    // pchEnc   : in  hex ciphertext produced by EncrptData
    // pchPlain : out hex plaintext; >= strlen(pchEnc) bytes is always safe
    int DecrptData(char* pchPriKey, char* pchEnc, char* pchPlain);

    // pchSign: out hex signature, >= ECC_SIGN_HEX_LEN bytes (129)
    int SignData(char* pchPriKey, char* pchPlain, char* pchSign);

    // Returns ECC_OK on valid signature, ECC_ERR_VERIFY on mismatch.
    int VerifyData(char* pchPubKey, char* pchPlain, char* pchSign);
};
```

---

## Return codes

All functions return `int`. `0` means success; negative means failure.
Constants are defined in [`CEccModule.h`](CEccModule.h):

| Code                        | Meaning                                       |
|-----------------------------|-----------------------------------------------|
| `ECC_OK` (0)                | Success                                       |
| `ECC_ERR_NULL_ARG` (-1)     | A required buffer pointer was `NULL`          |
| `ECC_ERR_KEYGEN` (-2)       | Key/ephemeral generation failed               |
| `ECC_ERR_KEY_PARSE` (-3)    | Key hex string wrong length / malformed point |
| `ECC_ERR_KEY_SERIALIZE` (-4)| Could not write key bytes                     |
| `ECC_ERR_ECDH` (-5)         | ECDH derivation failed                        |
| `ECC_ERR_KDF` (-6)          | HKDF derivation failed                        |
| `ECC_ERR_AES` (-7)          | AES-GCM failed — **also returned for tag mismatch (tampered ciphertext)** |
| `ECC_ERR_HEX` (-8)          | A hex input had bad chars or odd length       |
| `ECC_ERR_SIGN` (-9)         | ECDSA sign failed                             |
| `ECC_ERR_VERIFY` (-10)      | Signature did not verify under the given key  |
| `ECC_ERR_BUFFER_TOO_SMALL`  | (Unused in current impl; reserved.)           |
| `ECC_ERR_INTERNAL` (-12)    | Unexpected internal failure                   |
| `ECC_ERR_RNG` (-13)         | The pluggable RNG returned an error           |

---

## Buffer sizes

P-256 fixes every length except the ciphertext, which grows with the
plaintext. Recommended sizing rules:

```cpp
char pubKey[ECC_PUBKEY_HEX_LEN];     // 131 bytes
char priKey[ECC_PRIKEY_HEX_LEN];     // 65 bytes
char sig   [ECC_SIGN_HEX_LEN];       // 129 bytes
char enc   [ECC_ENC_OVERHEAD_HEX + 2*N];   // for N-byte plaintext
char plain [ECC_ENC_OVERHEAD_HEX + 2*N];   // safe: strlen(enc)+1 is enough
```

---

## Quick start example

```cpp
#include "CEccModule.h"
#include <cstdio>
#include <cstring>

static void StrToHex(const char* s, char* out)
{
    static const char d[] = "0123456789ABCDEF";
    size_t i = 0;
    for (; s[i]; ++i) {
        unsigned char b = (unsigned char)s[i];
        out[2*i]   = d[(b >> 4) & 0xF];
        out[2*i+1] = d[b & 0xF];
    }
    out[2*i] = '\0';
}

int main()
{
    CEccModule ecc;

    char pub[ECC_PUBKEY_HEX_LEN], pri[ECC_PRIKEY_HEX_LEN];
    ecc.GetKey(pub, pri);

    char msgHex[1024];
    StrToHex("Top-secret message.", msgHex);

    // Encrypt + Decrypt
    char enc[4096], dec[4096];
    ecc.EncrptData(pub, msgHex, enc);
    ecc.DecrptData(pri, enc, dec);   // dec == msgHex

    // Sign + Verify
    char sig[ECC_SIGN_HEX_LEN];
    ecc.SignData(pri, msgHex, sig);
    int ok = ecc.VerifyData(pub, msgHex, sig);   // ok == ECC_OK
    std::printf("verify = %d\n", ok);
    return 0;
}
```

Run the bundled demo for a full round-trip plus tamper tests:

```
> ecc_demo.exe
Public key  (130 hex chars): 0488B7140...CAFD
Private key (64 hex chars):  073B19C3...AB65
[OK] consecutive GetKey calls produce distinct keypairs
[OK] encrypt/decrypt round-trip
[OK] tampered ciphertext rejected (rc=-7)
[OK] verify good message
[OK] verify tampered message rejected (rc=-10)
[OK] verify under wrong public key rejected (rc=-10)
[OK] custom RNG is honored (identical seeds -> identical keys)
All tests passed.
```

---

## Pluggable RNG

By default the module uses OpenSSL's CSPRNG (`RAND_bytes`). To swap in
your own RNG, derive from `IEccRng` and call `SetRng(yourRng)`:

```cpp
class CMyRng : public IEccRng
{
public:
    int GenerateBytes(unsigned char* pBuf, std::size_t nLen) override {
        // Fill pBuf with nLen cryptographically random bytes.
        // Return ECC_OK on success, ECC_ERR_RNG on failure.
        ...
        return ECC_OK;
    }
};

CMyRng myRng;
CEccModule ecc;
ecc.SetRng(&myRng);          // affects all subsequent calls
// ... use ecc ...
ecc.SetRng(nullptr);         // restore the default CSPRNG
```

The module **never deletes** the RNG you pass; ownership stays with you.

The custom RNG is used for **every random byte the module produces**: long-
term key generation, ephemeral keys for encryption, and AES-GCM IVs. With a
deterministic seeded RNG (see `CSeedRng` in [`main.cpp`](main.cpp)) you get
fully reproducible operations — useful for tests, but obviously **not** for
production cryptography.

---

## Building

### Windows, offline (vendored OpenSSL)

Prerequisite: a MinGW-w64 g++ toolchain. The build script defaults to the
[msys2](https://www.msys2.org) layout at `C:\msys64\mingw64`. Override with
the `MINGW_DIR` environment variable if your install is elsewhere.

```bat
> build.bat
Building ecc_demo.exe (dynamic link, OpenSSL from ...third_party\openssl)...
Built ecc_demo.exe + libcrypto-3-x64.dll + libwinpthread-1.dll.

> ecc_demo.exe
... all tests pass ...
```

The build produces three files in the project root:

- `ecc_demo.exe`            — the demo binary (statically linked libgcc/libstdc++)
- `libcrypto-3-x64.dll`     — OpenSSL runtime, copied from `third_party/`
- `libwinpthread-1.dll`     — MinGW pthreads runtime, copied from `third_party/`

The `.exe` has only these two DLLs plus standard Windows libs
(`KERNEL32.dll`, `msvcrt.dll`) as dependencies, so it can be shipped to any
Windows machine without an internet connection.

### Linux / macOS (system OpenSSL)

Install OpenSSL development headers via your package manager, then:

```bash
$ sudo apt-get install libssl-dev          # Debian/Ubuntu
$ sudo dnf install openssl-devel           # Fedora/RHEL
$ brew install openssl                     # macOS

$ make
$ ./ecc_demo
... all tests pass ...
```

Pass `STATIC=1` to produce a fully-static binary (requires `libcrypto.a`
from a static OpenSSL package).

### MSVC + vcpkg

```cmd
> vcpkg install openssl:x64-windows
> cl /EHsc /std:c++17 ^
     CEccModule.cpp main.cpp ^
     /I<vcpkg>\installed\x64-windows\include ^
     <vcpkg>\installed\x64-windows\lib\libcrypto.lib ^
     ws2_32.lib crypt32.lib
```

(The vendored MinGW import library will **not** link with MSVC; use vcpkg
or a separate MSVC build of OpenSSL.)

---

## Vendored third-party files

Everything under [`third_party/openssl/`](third_party/openssl/) is copied
verbatim from [msys2](https://www.msys2.org) packages and is redistributed
under the OpenSSL license (Apache-2.0). No modifications.

| Source package | File(s) vendored                     | Size  |
|----------------|--------------------------------------|-------|
| `mingw-w64-x86_64-openssl` | `include/openssl/*.h` (142 files) | ~2 MB |
| `mingw-w64-x86_64-openssl` | `lib/libcrypto.a`                  | ~9 MB |
| `mingw-w64-x86_64-openssl` | `lib/libcrypto.dll.a`              | ~4 MB |
| `mingw-w64-x86_64-openssl` | `bin/libcrypto-3-x64.dll`          | ~5 MB |
| `mingw-w64-x86_64-libwinpthread` | `bin/libwinpthread-1.dll`    | ~63 KB |

**OpenSSL version: 3.6.2 (April 2026).** To upgrade, replace the files from
a newer msys2 package — the API used by this module (`EVP_PKEY`, `EC_KEY`,
`ECDSA_do_sign`, HKDF context) is stable across the 1.0.2 → 3.x range.

The compiler itself (MinGW-w64 g++) is **not** vendored. Install msys2
once and the rest of the build is self-contained.

---

## Cross-platform notes

- The C++ source uses only the standard library and OpenSSL — no Win32,
  no POSIX-only headers. Same source builds on Linux, macOS, and Windows.
- The build assumes a little-endian, 64-bit target. P-256 keys are sized
  for that explicitly.
- C++11 is the floor; C++17 also works (e.g. for the MSVC instructions
  above).
- OpenSSL 3.x deprecates the low-level `EC_KEY` API used internally. The
  build suppresses the deprecation warnings (`-Wno-deprecated-declarations`)
  because the deprecated symbols still work and are the simplest path that
  remains source-compatible all the way back to OpenSSL 1.0.2 — important
  if you need to ship to Windows XP, the last OS for which an official
  OpenSSL 1.0.2 binary exists.

---

## Security notes & limitations

- **Use the default RNG in production.** The `CSeedRng` example in
  `main.cpp` is a deterministic xorshift used only for testing — it is
  insecure by construction.
- **Public keys are not validated to be on the curve beyond the format
  check.** OpenSSL's `EC_POINT_oct2point` rejects malformed points and the
  derived shared secret with a hostile peer key is still unique, but a
  hardened deployment would add an explicit `EC_POINT_is_on_curve` check.
- **No replay protection.** Each call to `EncrptData` uses a fresh
  ephemeral keypair and random IV, so identical plaintexts produce distinct
  ciphertexts; but the module does not bind ciphertexts to a session,
  sender identity, or timestamp. Layer that in at the application level if
  needed.
- **Signature is non-deterministic.** `ECDSA_do_sign` uses a fresh random
  `k` each call (RFC 6979 deterministic signing is not enabled). Two sigs
  over the same message will differ, but both will verify.
- **Keys are not zeroed.** The private key hex string and intermediate
  scalar live in normal `std::vector`/`char` buffers. If you need to wipe
  them, do so at the call site after use.
