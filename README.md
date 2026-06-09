# CEccModule

A small, self-contained C++ class that wraps Elliptic Curve Cryptography
(NIST P-256) so a caller can do four things with a uniform `char*`-only,
hex-string API:

1. Generate a fresh public/private keypair.
2. Encrypt a plaintext under a public key (hybrid ECIES).
3. Decrypt that ciphertext with the matching private key.
4. Sign data with the private key and verify the signature with the public key.

The code is **cross-platform** (Windows XP through 11, Linux, macOS) and ships
with **two interchangeable crypto backends** so you can pick the trade-off that
fits your deployment:

| Backend     | Vendored under                | Link mode        | Runtime DLLs     | Final binary  | Min Windows  |
|-------------|-------------------------------|------------------|------------------|---------------|--------------|
| **OpenSSL** | `third_party/openssl/` (20 MB) | Dynamic libcrypto | libcrypto-3-x64.dll (5.3 MB) + libwinpthread-1.dll | ~714 KB + DLL | Vista        |
| **mbedTLS** | `third_party/mbedtls/` (6 MB)  | Static into .exe  | **none** (only system DLLs) | ~819 KB       | XP SP3       |

Both backends share the same `CEccModule.h` header and `main.cpp` test driver,
and they speak the **same wire format**: 65-byte uncompressed P-256 public
points, 32-byte raw private scalars, 64-byte raw `r‖s` ECDSA signatures,
ECIES blob = `ephPub‖IV‖tag‖AES-256-GCM(plaintext)`.

---

## Contents

- [Two backends, one API](#two-backends-one-api)
- [Cryptographic design](#cryptographic-design)
- [String formats (everything is hex)](#string-formats-everything-is-hex)
- [Files in this project](#files-in-this-project)
- [Public API](#public-api)
- [Return codes](#return-codes)
- [Buffer sizes](#buffer-sizes)
- [Quick start example](#quick-start-example)
- [Pluggable RNG](#pluggable-rng)
- [Building](#building)
- [Windows XP support](#windows-xp-support)
- [Vendored third-party files](#vendored-third-party-files)
- [Security notes & limitations](#security-notes--limitations)

---

## Two backends, one API

`CEccModule.h` is the **only** header your application sees. Both
implementations behave identically through that interface — same return codes,
same buffer sizes, same hex string formats.

```
CEccModule.h                 (shared public API)
├── CEccModule_openssl.cpp   (backend A: links libcrypto)
└── CEccModule_mbedtls.cpp   (backend B: compiles mbedTLS sources directly)
main.cpp                     (shared test driver — works with either backend)
```

Pick **OpenSSL** when:
- Your target machines already have OpenSSL (or you don't mind shipping the 5.3 MB DLL)
- You want the most-vetted crypto code in the industry
- You're on Vista+ or Linux only

Pick **mbedTLS** when:
- You want a **single self-contained .exe** with no DLLs alongside
- You need to ship to Windows XP / Server 2003
- You want a smaller distribution footprint (~819 KB vs ~6 MB)
- You're embedding into a system without a package manager

You can build both side by side and use them simultaneously — they produce
binary `ecc_demo_openssl.exe` and `ecc_demo_mbedtls.exe`, identical behavior.

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
| Random number source   | Pluggable via [`IEccRng`](CEccModule.h) interface   |

Default RNGs (override with `SetRng(myRng)`):
- **OpenSSL backend**: `RAND_bytes` (OpenSSL CSPRNG)
- **mbedTLS backend**: `CryptGenRandom` on Windows (advapi32, XP+), `/dev/urandom` on POSIX

### Why P-256 instead of a homemade curve?

Strength of an elliptic curve does **not** come from keeping the curve
coefficients secret — it comes from decades of public cryptanalysis. A random
homemade curve typically has small subgroup order, anomalous structure, or
other weaknesses that allow attacks vastly faster than brute force. Computing
the group order `n` correctly (needed for valid private keys) requires
Schoof's algorithm and is easy to get wrong. P-256 is the widely-vetted
default; both backends use it.

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

Decryption recomputes `S = ECDH(privKey, R)` and runs GCM in reverse.
AES-GCM's authentication tag detects any tampering of the ciphertext.

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

| Value           | Bytes  | Hex chars        |
|-----------------|--------|------------------|
| Public key      | 65     | **130**          |
| Private key     | 32     | **64**           |
| Signature       | 64     | **128**          |
| Ciphertext      | 93 + N | **186 + 2·N**    (N = plaintext-byte length) |

Macros in [`CEccModule.h`](CEccModule.h): `ECC_PUBKEY_HEX_LEN = 131`,
`ECC_PRIKEY_HEX_LEN = 65`, `ECC_SIGN_HEX_LEN = 129`,
`ECC_ENC_OVERHEAD_HEX = 187` (each includes the `\0` terminator).

---

## Files in this project

```
KGH/
├── CEccModule.h                    Public class + IEccRng interface + return codes
├── CEccModule_openssl.cpp          Backend A: OpenSSL implementation
├── CEccModule_mbedtls.cpp          Backend B: mbedTLS implementation
├── main.cpp                        Shared demo / test driver
├── build_openssl.bat               Windows build, OpenSSL backend
├── build_mbedtls.bat               Windows build, mbedTLS backend
├── build.bat                       Windows build, both backends
├── Makefile                        Linux/macOS/MinGW build, BACKEND=openssl|mbedtls|both
├── README.md                       This file
├── LICENSE                         Apache-2.0
└── third_party/
    ├── openssl/                    OpenSSL 3.6.2 vendored (headers + libs + DLLs)
    │   ├── include/openssl/        142 headers
    │   ├── lib/libcrypto.a         Static archive (9.5 MB)
    │   ├── lib/libcrypto.dll.a     Import library (3.9 MB)
    │   └── bin/
    │       ├── libcrypto-3-x64.dll Runtime DLL (5.3 MB)
    │       └── libwinpthread-1.dll MinGW pthreads runtime (63 KB)
    └── mbedtls/                    mbedTLS 2.28.10 LTS vendored (sources)
        ├── library/*.c             96 source files (19 actually compiled)
        ├── include/mbedtls/*.h     Headers (config.h is project-specific)
        ├── include/psa/*.h         PSA crypto API headers
        ├── LICENSE                 mbedTLS license
        └── MBEDTLS_README.md       mbedTLS upstream README
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
    // Pass nullptr to revert to the default CSPRNG.
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
| `ECC_ERR_INTERNAL` (-12)    | Unexpected internal failure                   |
| `ECC_ERR_RNG` (-13)         | The pluggable RNG returned an error           |

---

## Buffer sizes

P-256 fixes every length except the ciphertext, which grows with the
plaintext. Recommended sizing rules:

```cpp
char pubKey[ECC_PUBKEY_HEX_LEN];           // 131 bytes
char priKey[ECC_PRIKEY_HEX_LEN];           // 65 bytes
char sig   [ECC_SIGN_HEX_LEN];             // 129 bytes
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

    char enc[4096], dec[4096];
    ecc.EncrptData(pub, msgHex, enc);
    ecc.DecrptData(pri, enc, dec);   // dec == msgHex

    char sig[ECC_SIGN_HEX_LEN];
    ecc.SignData(pri, msgHex, sig);
    int ok = ecc.VerifyData(pub, msgHex, sig);   // ok == ECC_OK
    std::printf("verify = %d\n", ok);
    return 0;
}
```

The same code compiles and runs against either backend — just link the
appropriate `CEccModule_*.cpp` source file.

---

## Pluggable RNG

By default each backend uses a sensible CSPRNG (OpenSSL `RAND_bytes` or
Windows `CryptGenRandom` / POSIX `/dev/urandom`). To swap in your own,
derive from `IEccRng` and call `SetRng(yourRng)`:

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

### Windows (vendored libs, no internet needed)

Prerequisite: a MinGW-w64 toolchain (`gcc` + `g++`). The build scripts
default to msys2's `C:\msys64\mingw64`; override with `set MINGW_DIR=...`
if elsewhere.

```bat
> build.bat                 :: builds BOTH backends
> build_openssl.bat         :: builds only ecc_demo_openssl.exe (+ DLLs)
> build_mbedtls.bat         :: builds only ecc_demo_mbedtls.exe (standalone)
```

Outputs in the project root:

- `ecc_demo_openssl.exe`     — 714 KB. **Needs** `libcrypto-3-x64.dll` and
  `libwinpthread-1.dll` next to it (the scripts copy them from `third_party/`).
- `ecc_demo_mbedtls.exe`     — 819 KB. **No** DLLs needed. Only system
  imports: `KERNEL32.dll`, `msvcrt.dll`, `ADVAPI32.dll`.

### Linux / macOS

For the OpenSSL backend, install OpenSSL dev headers via your package manager:

```bash
sudo apt-get install build-essential libssl-dev   # Debian/Ubuntu
sudo dnf install gcc-c++ make openssl-devel       # Fedora/RHEL
brew install openssl                              # macOS
```

For the mbedTLS backend you don't need to install anything — the vendored
source is compiled in.

```bash
make                        # both backends
make BACKEND=openssl        # only OpenSSL (ecc_demo_openssl)
make BACKEND=mbedtls        # only mbedTLS (ecc_demo_mbedtls)
make STATIC=1               # force static link
```

### MSVC + vcpkg (OpenSSL backend only)

```cmd
> vcpkg install openssl:x64-windows
> cl /EHsc /std:c++17 ^
     CEccModule_openssl.cpp main.cpp ^
     /I<vcpkg>\installed\x64-windows\include ^
     <vcpkg>\installed\x64-windows\lib\libcrypto.lib ^
     ws2_32.lib crypt32.lib
```

The vendored MinGW import library does **not** link with MSVC; use vcpkg
or a separate MSVC build of OpenSSL.

---

## Windows XP support

The **mbedTLS backend** is XP-compatible by design:

- All crypto is statically linked into the .exe.
- The default RNG uses `CryptGenRandom` from `advapi32.dll`, present on
  every NT-line Windows from 2000 onward. No `BCrypt`/`bcrypt.dll`
  (Vista-only) is ever called.
- mbedTLS 2.28 LTS is pure C99 and has no platform-specific runtime
  requirements beyond the C standard library and (on Windows) advapi32.
- The build script passes `-D_WIN32_WINNT=0x0501` to constrain the
  Windows API surface to what XP exposes.
- `-static-libgcc -static-libstdc++ -static` removes all non-system DLL
  dependencies.

The **OpenSSL backend** is **not** XP-compatible because OpenSSL 3.x
dropped XP support upstream. If you need OpenSSL on XP, link against
OpenSSL 1.0.2 instead (the same `CEccModule_openssl.cpp` source compiles
unchanged against it).

To actually build for XP you need an XP-capable toolchain:

- **MinGW-w64** built with `-D_WIN32_WINNT=0x0501` (msys2's mingw64 works).
- **MSVC** with the v141_xp platform toolset (free, separate VS install component).

The C++ source itself uses only `<cstring>`, `<memory>`, `<vector>` and
the chosen crypto library — none of which need anything newer than XP.

---

## Vendored third-party files

Everything under [`third_party/`](third_party/) is redistributed under
Apache-2.0 (matching this repository's license). No modifications other
than the project-specific `mbedtls/include/mbedtls/config.h`.

| Library    | Source                                          | Version    | Vendored size |
|------------|-------------------------------------------------|------------|---------------|
| OpenSSL    | msys2 `mingw-w64-x86_64-openssl` package        | **3.6.2**  | ~20 MB        |
| winpthread | msys2 `mingw-w64-x86_64-libwinpthread` package  | (current)  | ~63 KB        |
| mbedTLS    | [Mbed-TLS/mbedtls](https://github.com/Mbed-TLS/mbedtls) (tag `mbedtls-2.28.10`) | **2.28.10 LTS** | ~6 MB |

To upgrade either library, replace the files in place — the public APIs
this project uses (OpenSSL: `EVP_PKEY`, `EC_KEY`, `ECDSA_do_sign`, HKDF;
mbedTLS: `mbedtls_ecdh_compute_shared`, `mbedtls_ecdsa_sign`,
`mbedtls_gcm_*`, `mbedtls_hkdf`) are stable.

The compilers (MinGW-w64 g++, gcc, Linux g++) are **not** vendored.

---

## Security notes & limitations

- **Use the default RNG in production.** The `CSeedRng` example in
  `main.cpp` is a deterministic xorshift used only for testing — it is
  insecure by construction.
- **Public keys are validated to be on the curve.** Both backends call
  `EC_POINT_oct2point` / `mbedtls_ecp_check_pubkey` and reject malformed
  inputs. (The mbedTLS backend's check is slightly stronger.)
- **No replay protection.** Each call to `EncrptData` uses a fresh
  ephemeral keypair and random IV, so identical plaintexts produce distinct
  ciphertexts; but the module does not bind ciphertexts to a session,
  sender identity, or timestamp. Layer that in at the application level if
  needed.
- **Signature is non-deterministic.** Both backends use a fresh random
  `k` each call (RFC 6979 deterministic signing is not enabled). Two sigs
  over the same message will differ, but both will verify.
- **Keys are not zeroed.** The private key hex string and intermediate
  scalar live in normal `std::vector`/`char` buffers. If you need to wipe
  them, do so at the call site after use.
- **Backends are wire-compatible by spec, not byte-identical at the API
  level.** A keypair generated by either backend can be loaded and used by
  the other (same 65/32-byte raw formats). A ciphertext from one backend
  can be decrypted by the other (same `ephPub‖iv‖tag‖ct` layout, same
  HKDF info string `CEccModule-ECIES-v1`). A signature from one verifies
  under the other (same raw `r‖s` format).
