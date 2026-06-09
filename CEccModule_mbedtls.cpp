// CEccModule_mbedtls.cpp
// mbedTLS 2.28 backend for CEccModule.
//
// Same public API as the OpenSSL backend (CEccModule_mbedtls.cpp and
// CEccModule_openssl.cpp are link-time alternatives sharing the same
// CEccModule.h header). Both produce byte-identical:
//   - 65-byte uncompressed P-256 public point (04 || X || Y)
//   - 32-byte raw scalar private key
//   - 64-byte raw r||s ECDSA signature
//   - ECIES blob = ephPub(65) || iv(12) || tag(16) || AES-256-GCM ciphertext
// All exposed as uppercase hex strings.
//
// Build: see build_mbedtls.bat / Makefile (BACKEND=mbedtls).
//
// Cross-platform notes:
//   - Pure C++11 + mbedTLS 2.28 (C99). No Win32/POSIX headers in this file
//     except inside the default RNG fallback below.
//   - The default RNG uses CryptGenRandom on Windows (advapi32, present on
//     XP+) and /dev/urandom on POSIX. Supply your own IEccRng via SetRng()
//     to override.

#include "CEccModule.h"

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"

#include <cstring>
#include <cstdio>
#include <vector>

#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <wincrypt.h>
  // CryptGenRandom lives in advapi32, present on every NT-line Windows from 2000+.
  // MSVC: auto-link; MinGW/g++ specifies -ladvapi32 in the build script instead.
  #if defined(_MSC_VER)
    #pragma comment(lib, "advapi32.lib")
  #endif
#endif

namespace {

// ----- Curve / cipher constants ---------------------------------------------
const mbedtls_ecp_group_id kCurveId = MBEDTLS_ECP_DP_SECP256R1;
const size_t kScalarLen = 32;     // P-256 private key
const size_t kPointLen  = 65;     // 04 || X(32) || Y(32)
const size_t kAesKeyLen = 32;     // AES-256
const size_t kGcmIvLen  = 12;
const size_t kGcmTagLen = 16;
const size_t kSigRSLen  = 64;     // r(32) || s(32)

// ----- Hex helpers (mirror the OpenSSL backend exactly) ---------------------
int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int HexDecode(const char* hex, std::vector<unsigned char>& out)
{
    if (!hex) return ECC_ERR_HEX;
    size_t len = std::strlen(hex);
    if (len & 1) return ECC_ERR_HEX;
    out.resize(len / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = HexNibble(hex[2 * i]);
        int lo = HexNibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return ECC_ERR_HEX;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return ECC_OK;
}

void HexEncode(const unsigned char* in, size_t n, char* out)
{
    static const char d[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; ++i) {
        out[2 * i]     = d[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = d[in[i] & 0xF];
    }
    out[2 * n] = '\0';
}

// ----- Default RNG: XP-compatible CryptGenRandom / POSIX /dev/urandom -------
class CDefaultRng : public IEccRng
{
public:
    int GenerateBytes(unsigned char* pBuf, std::size_t nLen)
    {
#if defined(_WIN32)
        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                                  CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
            return ECC_ERR_RNG;
        BOOL ok = CryptGenRandom(hProv, (DWORD)nLen, pBuf);
        CryptReleaseContext(hProv, 0);
        return ok ? ECC_OK : ECC_ERR_RNG;
#else
        FILE* f = std::fopen("/dev/urandom", "rb");
        if (!f) return ECC_ERR_RNG;
        size_t r = std::fread(pBuf, 1, nLen, f);
        std::fclose(f);
        return (r == nLen) ? ECC_OK : ECC_ERR_RNG;
#endif
    }
};
CDefaultRng g_DefaultRng;

// mbedTLS RNG callback adapter: passes IEccRng* as the opaque context.
int MbedRngCallback(void* p_rng, unsigned char* out, size_t n)
{
    IEccRng* rng = static_cast<IEccRng*>(p_rng);
    return (rng->GenerateBytes(out, n) == ECC_OK) ? 0 : -1;
}

// ----- ECDH + HKDF-SHA256 ---------------------------------------------------
int DeriveSharedKey(mbedtls_ecp_group& grp,
                    const mbedtls_mpi& d,
                    const mbedtls_ecp_point& peerQ,
                    IEccRng* rng,
                    unsigned char outKey[/*kAesKeyLen*/])
{
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    int rc = mbedtls_ecdh_compute_shared(&grp, &z, &peerQ, &d,
                                         MbedRngCallback, rng);
    if (rc != 0) { mbedtls_mpi_free(&z); return ECC_ERR_ECDH; }

    unsigned char secret[kScalarLen];
    rc = mbedtls_mpi_write_binary(&z, secret, kScalarLen);
    mbedtls_mpi_free(&z);
    if (rc != 0) return ECC_ERR_ECDH;

    static const unsigned char kInfo[] = "CEccModule-ECIES-v1";
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return ECC_ERR_KDF;
    rc = mbedtls_hkdf(md, NULL, 0, secret, kScalarLen,
                      kInfo, sizeof(kInfo) - 1, outKey, kAesKeyLen);
    return (rc == 0) ? ECC_OK : ECC_ERR_KDF;
}

// ----- AES-256-GCM ----------------------------------------------------------
int AesGcmEnc(const unsigned char key[/*kAesKeyLen*/],
              const unsigned char iv[/*kGcmIvLen*/],
              const unsigned char* pt, size_t ptLen,
              unsigned char* ct, /* same length as pt */
              unsigned char tag[/*kGcmTagLen*/])
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                key, (unsigned int)(kAesKeyLen * 8));
    if (rc != 0) { mbedtls_gcm_free(&ctx); return ECC_ERR_AES; }
    rc = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, ptLen,
                                   iv, kGcmIvLen,
                                   NULL, 0,
                                   pt, ct,
                                   kGcmTagLen, tag);
    mbedtls_gcm_free(&ctx);
    return (rc == 0) ? ECC_OK : ECC_ERR_AES;
}

int AesGcmDec(const unsigned char key[/*kAesKeyLen*/],
              const unsigned char iv[/*kGcmIvLen*/],
              const unsigned char* ct, size_t ctLen,
              const unsigned char tag[/*kGcmTagLen*/],
              unsigned char* pt)
{
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                                key, (unsigned int)(kAesKeyLen * 8));
    if (rc != 0) { mbedtls_gcm_free(&ctx); return ECC_ERR_AES; }
    rc = mbedtls_gcm_auth_decrypt(&ctx, ctLen,
                                  iv, kGcmIvLen,
                                  NULL, 0,
                                  tag, kGcmTagLen,
                                  ct, pt);
    mbedtls_gcm_free(&ctx);
    return (rc == 0) ? ECC_OK : ECC_ERR_AES;   // tag mismatch -> -7
}

int Sha256(const unsigned char* msg, size_t len, unsigned char out[/*32*/])
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    if (mbedtls_sha256_starts_ret(&ctx, 0) != 0)      goto fail;
    if (mbedtls_sha256_update_ret(&ctx, msg, len) != 0) goto fail;
    if (mbedtls_sha256_finish_ret(&ctx, out) != 0)    goto fail;
    mbedtls_sha256_free(&ctx);
    return ECC_OK;
fail:
    mbedtls_sha256_free(&ctx);
    return ECC_ERR_INTERNAL;
}

// ----- Group cache (mbedtls_ecp_group_load is reentrant but heavy) ----------
int LoadGroup(mbedtls_ecp_group& grp)
{
    return mbedtls_ecp_group_load(&grp, kCurveId) == 0 ? ECC_OK : ECC_ERR_KEYGEN;
}

} // namespace

// =============================================================================
// CEccModule (mbedTLS backend)
// =============================================================================

CEccModule::CEccModule() : m_pRng(&g_DefaultRng) {}
CEccModule::~CEccModule() {}

void CEccModule::SetRng(IEccRng* pRng)
{
    m_pRng = pRng ? pRng : &g_DefaultRng;
}

int CEccModule::GetKey(char* pchPubKey, char* pchPriKey)
{
    if (!pchPubKey || !pchPriKey) return ECC_ERR_NULL_ARG;

    mbedtls_ecp_group grp; mbedtls_mpi d; mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    int rc = LoadGroup(grp);
    if (rc != ECC_OK) goto cleanup;

    if (mbedtls_ecp_gen_keypair(&grp, &d, &Q, MbedRngCallback, m_pRng) != 0) {
        rc = ECC_ERR_KEYGEN; goto cleanup;
    }

    {
        unsigned char privBytes[kScalarLen];
        if (mbedtls_mpi_write_binary(&d, privBytes, kScalarLen) != 0) {
            rc = ECC_ERR_KEY_SERIALIZE; goto cleanup;
        }
        unsigned char pubBytes[kPointLen];
        size_t pubLen = 0;
        if (mbedtls_ecp_point_write_binary(&grp, &Q,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           &pubLen, pubBytes, sizeof(pubBytes)) != 0
            || pubLen != kPointLen) {
            rc = ECC_ERR_KEY_SERIALIZE; goto cleanup;
        }
        HexEncode(pubBytes, kPointLen, pchPubKey);
        HexEncode(privBytes, kScalarLen, pchPriKey);
        rc = ECC_OK;
    }

cleanup:
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

int CEccModule::EncrptData(char* pchPubKey, char* pchPlain, char* pchEnc)
{
    if (!pchPubKey || !pchPlain || !pchEnc) return ECC_ERR_NULL_ARG;

    std::vector<unsigned char> pubBytes;
    int rc = HexDecode(pchPubKey, pubBytes);
    if (rc != ECC_OK) return rc;
    if (pubBytes.size() != kPointLen || pubBytes[0] != 0x04) return ECC_ERR_KEY_PARSE;

    std::vector<unsigned char> plainBytes;
    rc = HexDecode(pchPlain, plainBytes);
    if (rc != ECC_OK) return rc;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point recipQ, ephQ;
    mbedtls_mpi ephD;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&recipQ);
    mbedtls_ecp_point_init(&ephQ);
    mbedtls_mpi_init(&ephD);

    if ((rc = LoadGroup(grp)) != ECC_OK) goto cleanup;

    if (mbedtls_ecp_point_read_binary(&grp, &recipQ,
                                      pubBytes.data(), pubBytes.size()) != 0
        || mbedtls_ecp_check_pubkey(&grp, &recipQ) != 0) {
        rc = ECC_ERR_KEY_PARSE; goto cleanup;
    }

    if (mbedtls_ecp_gen_keypair(&grp, &ephD, &ephQ, MbedRngCallback, m_pRng) != 0) {
        rc = ECC_ERR_KEYGEN; goto cleanup;
    }

    {
        unsigned char aesKey[kAesKeyLen];
        if ((rc = DeriveSharedKey(grp, ephD, recipQ, m_pRng, aesKey)) != ECC_OK) goto cleanup;

        unsigned char iv[kGcmIvLen];
        if ((rc = m_pRng->GenerateBytes(iv, kGcmIvLen)) != ECC_OK) goto cleanup;

        std::vector<unsigned char> ct(plainBytes.size());
        unsigned char tag[kGcmTagLen];
        if ((rc = AesGcmEnc(aesKey, iv,
                            plainBytes.empty() ? NULL : plainBytes.data(),
                            plainBytes.size(),
                            ct.data(), tag)) != ECC_OK) goto cleanup;

        unsigned char ephPub[kPointLen];
        size_t ephLen = 0;
        if (mbedtls_ecp_point_write_binary(&grp, &ephQ,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED,
                                           &ephLen, ephPub, sizeof(ephPub)) != 0
            || ephLen != kPointLen) {
            rc = ECC_ERR_KEY_SERIALIZE; goto cleanup;
        }

        size_t blobLen = kPointLen + kGcmIvLen + kGcmTagLen + ct.size();
        std::vector<unsigned char> blob(blobLen);
        size_t off = 0;
        std::memcpy(blob.data() + off, ephPub, kPointLen); off += kPointLen;
        std::memcpy(blob.data() + off, iv,     kGcmIvLen); off += kGcmIvLen;
        std::memcpy(blob.data() + off, tag,    kGcmTagLen); off += kGcmTagLen;
        if (!ct.empty()) std::memcpy(blob.data() + off, ct.data(), ct.size());

        HexEncode(blob.data(), blob.size(), pchEnc);
        rc = ECC_OK;
    }

cleanup:
    mbedtls_mpi_free(&ephD);
    mbedtls_ecp_point_free(&ephQ);
    mbedtls_ecp_point_free(&recipQ);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

int CEccModule::DecrptData(char* pchPriKey, char* pchEnc, char* pchPlain)
{
    if (!pchPriKey || !pchEnc || !pchPlain) return ECC_ERR_NULL_ARG;

    std::vector<unsigned char> privBytes;
    int rc = HexDecode(pchPriKey, privBytes);
    if (rc != ECC_OK) return rc;
    if (privBytes.size() != kScalarLen) return ECC_ERR_KEY_PARSE;

    std::vector<unsigned char> blob;
    rc = HexDecode(pchEnc, blob);
    if (rc != ECC_OK) return rc;
    if (blob.size() < kPointLen + kGcmIvLen + kGcmTagLen) return ECC_ERR_INTERNAL;

    size_t off = 0;
    const unsigned char* ephPub = blob.data() + off; off += kPointLen;
    const unsigned char* iv     = blob.data() + off; off += kGcmIvLen;
    const unsigned char* tag    = blob.data() + off; off += kGcmTagLen;
    const unsigned char* ct     = blob.data() + off;
    size_t ctLen                = blob.size() - off;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point ephQ;
    mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&ephQ);
    mbedtls_mpi_init(&d);

    if ((rc = LoadGroup(grp)) != ECC_OK) goto cleanup;

    if (mbedtls_mpi_read_binary(&d, privBytes.data(), privBytes.size()) != 0) {
        rc = ECC_ERR_KEY_PARSE; goto cleanup;
    }
    if (mbedtls_ecp_point_read_binary(&grp, &ephQ, ephPub, kPointLen) != 0
        || mbedtls_ecp_check_pubkey(&grp, &ephQ) != 0) {
        rc = ECC_ERR_KEY_PARSE; goto cleanup;
    }

    {
        unsigned char aesKey[kAesKeyLen];
        if ((rc = DeriveSharedKey(grp, d, ephQ, m_pRng, aesKey)) != ECC_OK) goto cleanup;

        std::vector<unsigned char> pt(ctLen);
        if ((rc = AesGcmDec(aesKey, iv, ct, ctLen, tag, pt.data())) != ECC_OK) goto cleanup;

        HexEncode(pt.data(), pt.size(), pchPlain);
        rc = ECC_OK;
    }

cleanup:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&ephQ);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

int CEccModule::SignData(char* pchPriKey, char* pchPlain, char* pchSign)
{
    if (!pchPriKey || !pchPlain || !pchSign) return ECC_ERR_NULL_ARG;

    std::vector<unsigned char> privBytes;
    int rc = HexDecode(pchPriKey, privBytes);
    if (rc != ECC_OK) return rc;
    if (privBytes.size() != kScalarLen) return ECC_ERR_KEY_PARSE;

    std::vector<unsigned char> msg;
    rc = HexDecode(pchPlain, msg);
    if (rc != ECC_OK) return rc;

    unsigned char hash[32];
    if ((rc = Sha256(msg.empty() ? (const unsigned char*)"" : msg.data(),
                     msg.size(), hash)) != ECC_OK) return rc;

    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((rc = LoadGroup(grp)) != ECC_OK) goto cleanup;
    if (mbedtls_mpi_read_binary(&d, privBytes.data(), privBytes.size()) != 0) {
        rc = ECC_ERR_KEY_PARSE; goto cleanup;
    }
    if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash),
                           MbedRngCallback, m_pRng) != 0) {
        rc = ECC_ERR_SIGN; goto cleanup;
    }

    {
        unsigned char rs[kSigRSLen] = {0};
        if (mbedtls_mpi_write_binary(&r, rs,      32) != 0 ||
            mbedtls_mpi_write_binary(&s, rs + 32, 32) != 0) {
            rc = ECC_ERR_SIGN; goto cleanup;
        }
        HexEncode(rs, kSigRSLen, pchSign);
        rc = ECC_OK;
    }

cleanup:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return rc;
}

int CEccModule::VerifyData(char* pchPubKey, char* pchPlain, char* pchSign)
{
    if (!pchPubKey || !pchPlain || !pchSign) return ECC_ERR_NULL_ARG;

    std::vector<unsigned char> pubBytes;
    int rc = HexDecode(pchPubKey, pubBytes);
    if (rc != ECC_OK) return rc;
    if (pubBytes.size() != kPointLen || pubBytes[0] != 0x04) return ECC_ERR_KEY_PARSE;

    std::vector<unsigned char> rs;
    rc = HexDecode(pchSign, rs);
    if (rc != ECC_OK) return rc;
    if (rs.size() != kSigRSLen) return ECC_ERR_VERIFY;

    std::vector<unsigned char> msg;
    rc = HexDecode(pchPlain, msg);
    if (rc != ECC_OK) return rc;

    unsigned char hash[32];
    if ((rc = Sha256(msg.empty() ? (const unsigned char*)"" : msg.data(),
                     msg.size(), hash)) != ECC_OK) return rc;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((rc = LoadGroup(grp)) != ECC_OK) goto cleanup;
    if (mbedtls_ecp_point_read_binary(&grp, &Q,
                                      pubBytes.data(), pubBytes.size()) != 0
        || mbedtls_ecp_check_pubkey(&grp, &Q) != 0) {
        rc = ECC_ERR_KEY_PARSE; goto cleanup;
    }
    if (mbedtls_mpi_read_binary(&r, rs.data(),      32) != 0 ||
        mbedtls_mpi_read_binary(&s, rs.data() + 32, 32) != 0) {
        rc = ECC_ERR_VERIFY; goto cleanup;
    }

    rc = (mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &Q, &r, &s) == 0)
         ? ECC_OK : ECC_ERR_VERIFY;

cleanup:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return rc;
}
