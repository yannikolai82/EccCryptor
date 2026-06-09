// CEccModule.cpp
// NIST P-256 keygen, ECIES (ECDH + HKDF-SHA256 + AES-256-GCM), ECDSA-SHA256
// with raw r||s output. All strings are uppercase hex.
//
// Build (Linux / MSYS2):
//   g++ -std=c++11 -O2 -Wno-deprecated-declarations CEccModule.cpp main.cpp -lcrypto -o ecc_demo
// Build (MSVC + vcpkg OpenSSL):
//   cl /EHsc /std:c++17 CEccModule.cpp main.cpp libcrypto.lib
//
// OpenSSL 1.0.2 .. 3.x are all supported. The low-level EC_KEY / ECDSA_do_sign
// path is used to keep behaviour identical across versions and to allow the
// raw r||s signature encoding the caller asked for. The deprecation warnings
// in 3.x are suppressed by -Wno-deprecated-declarations.

#include "CEccModule.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <memory>
#include <vector>

namespace {

// ----- Curve / cipher constants ---------------------------------------------
const int    kCurveNid  = NID_X9_62_prime256v1;   // secp256r1 / P-256
const size_t kScalarLen = 32;                     // private key bytes
const size_t kPointLen  = 65;                     // 04 || X(32) || Y(32)
const size_t kAesKeyLen = 32;                     // AES-256
const size_t kGcmIvLen  = 12;
const size_t kGcmTagLen = 16;
const size_t kSigRSLen  = 64;                     // r(32) || s(32)

// ----- Hex helpers -----------------------------------------------------------
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

// ----- Default RNG = OpenSSL CSPRNG -----------------------------------------
class CDefaultRng : public IEccRng
{
public:
    int GenerateBytes(unsigned char* pBuf, std::size_t nLen)
    {
        return (RAND_bytes(pBuf, (int)nLen) == 1) ? ECC_OK : ECC_ERR_RNG;
    }
};
CDefaultRng g_DefaultRng;

// ----- Smart pointer deleters -----------------------------------------------
struct BNDel    { void operator()(BIGNUM* p)         const { if (p) BN_free(p); } };
struct ECPDel   { void operator()(EC_POINT* p)       const { if (p) EC_POINT_free(p); } };
struct ECGDel   { void operator()(EC_GROUP* p)       const { if (p) EC_GROUP_free(p); } };
struct ECKDel   { void operator()(EC_KEY* p)         const { if (p) EC_KEY_free(p); } };
struct PKeyDel  { void operator()(EVP_PKEY* p)       const { if (p) EVP_PKEY_free(p); } };
struct PCtxDel  { void operator()(EVP_PKEY_CTX* p)   const { if (p) EVP_PKEY_CTX_free(p); } };
struct CipDel   { void operator()(EVP_CIPHER_CTX* p) const { if (p) EVP_CIPHER_CTX_free(p); } };
struct MdCtxDel { void operator()(EVP_MD_CTX* p)     const { if (p) EVP_MD_CTX_free(p); } };
struct SigDel   { void operator()(ECDSA_SIG* p)      const { if (p) ECDSA_SIG_free(p); } };

typedef std::unique_ptr<BIGNUM,         BNDel>   BNPtr;
typedef std::unique_ptr<EC_POINT,       ECPDel>  ECPPtr;
typedef std::unique_ptr<EC_GROUP,       ECGDel>  ECGPtr;
typedef std::unique_ptr<EC_KEY,         ECKDel>  ECKPtr;
typedef std::unique_ptr<EVP_PKEY,       PKeyDel> PKeyPtr;
typedef std::unique_ptr<EVP_PKEY_CTX,   PCtxDel> PCtxPtr;
typedef std::unique_ptr<EVP_CIPHER_CTX, CipDel>  CipPtr;
typedef std::unique_ptr<EVP_MD_CTX,     MdCtxDel> MdCtxPtr;
typedef std::unique_ptr<ECDSA_SIG,      SigDel>  SigPtr;

// ----- Pluggable-RNG scalar generation (rejection sampling) -----------------
// Returns d in [1, n-1] using bytes from rng.
int GenScalar(IEccRng* rng, const BIGNUM* order, BIGNUM* outD)
{
    int orderBits  = BN_num_bits(order);
    int orderBytes = (orderBits + 7) / 8;
    std::vector<unsigned char> buf(orderBytes);
    for (int tries = 0; tries < 64; ++tries) {
        int rc = rng->GenerateBytes(buf.data(), buf.size());
        if (rc != ECC_OK) return rc;
        int excessBits = orderBytes * 8 - orderBits;
        if (excessBits > 0) buf[0] &= (unsigned char)(0xFF >> excessBits);
        if (!BN_bin2bn(buf.data(), (int)buf.size(), outD)) return ECC_ERR_INTERNAL;
        if (!BN_is_zero(outD) && BN_cmp(outD, order) < 0) return ECC_OK;
    }
    return ECC_ERR_RNG;
}

// EC_KEY from a private scalar; computes Q = d*G.
EC_KEY* MakeECKeyFromScalar(const BIGNUM* d, const EC_GROUP* g)
{
    EC_KEY* ec = EC_KEY_new();
    if (!ec) return nullptr;
    if (EC_KEY_set_group(ec, g) != 1)                { EC_KEY_free(ec); return nullptr; }
    if (EC_KEY_set_private_key(ec, d) != 1)          { EC_KEY_free(ec); return nullptr; }
    ECPPtr Q(EC_POINT_new(g));
    if (!Q)                                          { EC_KEY_free(ec); return nullptr; }
    if (EC_POINT_mul(g, Q.get(), d, nullptr, nullptr, nullptr) != 1)
                                                     { EC_KEY_free(ec); return nullptr; }
    if (EC_KEY_set_public_key(ec, Q.get()) != 1)     { EC_KEY_free(ec); return nullptr; }
    return ec;
}

int SerializePublicPoint(const EC_KEY* ec, unsigned char out[/*kPointLen*/])
{
    const EC_GROUP* g = EC_KEY_get0_group(ec);
    const EC_POINT* Q = EC_KEY_get0_public_key(ec);
    size_t n = EC_POINT_point2oct(g, Q, POINT_CONVERSION_UNCOMPRESSED,
                                  out, kPointLen, nullptr);
    return (n == kPointLen) ? ECC_OK : ECC_ERR_KEY_SERIALIZE;
}

int LoadPrivateKeyFromHex(const char* hex, EVP_PKEY** outPkey)
{
    std::vector<unsigned char> bytes;
    int rc = HexDecode(hex, bytes);
    if (rc != ECC_OK) return rc;
    if (bytes.size() != kScalarLen) return ECC_ERR_KEY_PARSE;

    ECGPtr group(EC_GROUP_new_by_curve_name(kCurveNid));
    if (!group) return ECC_ERR_KEY_PARSE;
    BNPtr d(BN_bin2bn(bytes.data(), (int)bytes.size(), nullptr));
    if (!d) return ECC_ERR_KEY_PARSE;

    EC_KEY* ec = MakeECKeyFromScalar(d.get(), group.get());
    if (!ec) return ECC_ERR_KEY_PARSE;

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey)                                   { EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }
    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1)   { EVP_PKEY_free(pkey); EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }
    // pkey now owns ec.
    *outPkey = pkey;
    return ECC_OK;
}

int LoadPublicKeyFromHex(const char* hex, EVP_PKEY** outPkey)
{
    std::vector<unsigned char> bytes;
    int rc = HexDecode(hex, bytes);
    if (rc != ECC_OK) return rc;
    if (bytes.size() != kPointLen || bytes[0] != 0x04) return ECC_ERR_KEY_PARSE;

    ECGPtr group(EC_GROUP_new_by_curve_name(kCurveNid));
    if (!group) return ECC_ERR_KEY_PARSE;

    EC_KEY* ec = EC_KEY_new();
    if (!ec) return ECC_ERR_KEY_PARSE;
    if (EC_KEY_set_group(ec, group.get()) != 1)       { EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }
    ECPPtr Q(EC_POINT_new(group.get()));
    if (!Q)                                            { EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }
    if (EC_POINT_oct2point(group.get(), Q.get(), bytes.data(), bytes.size(), nullptr) != 1)
                                                       { EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }
    if (EC_KEY_set_public_key(ec, Q.get()) != 1)       { EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey)                                         { EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }
    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1)         { EVP_PKEY_free(pkey); EC_KEY_free(ec); return ECC_ERR_KEY_PARSE; }
    *outPkey = pkey;
    return ECC_OK;
}

// ----- ECDH + HKDF-SHA256 ---------------------------------------------------
int DeriveSharedKey(EVP_PKEY* priv, EVP_PKEY* peerPub,
                    unsigned char outKey[/*kAesKeyLen*/])
{
    PCtxPtr ctx(EVP_PKEY_CTX_new(priv, nullptr));
    if (!ctx) return ECC_ERR_ECDH;
    if (EVP_PKEY_derive_init(ctx.get()) <= 0)              return ECC_ERR_ECDH;
    if (EVP_PKEY_derive_set_peer(ctx.get(), peerPub) <= 0) return ECC_ERR_ECDH;
    size_t sl = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &sl) <= 0)     return ECC_ERR_ECDH;
    std::vector<unsigned char> secret(sl);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &sl) <= 0) return ECC_ERR_ECDH;

    PCtxPtr kctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!kctx) return ECC_ERR_KDF;
    if (EVP_PKEY_derive_init(kctx.get()) <= 0)             return ECC_ERR_KDF;
    if (EVP_PKEY_CTX_set_hkdf_md(kctx.get(), EVP_sha256()) <= 0) return ECC_ERR_KDF;
    if (EVP_PKEY_CTX_set1_hkdf_key(kctx.get(), secret.data(), (int)secret.size()) <= 0)
                                                            return ECC_ERR_KDF;
    static const unsigned char kInfo[] = "CEccModule-ECIES-v1";
    if (EVP_PKEY_CTX_add1_hkdf_info(kctx.get(), kInfo, (int)sizeof(kInfo) - 1) <= 0)
                                                            return ECC_ERR_KDF;
    size_t ol = kAesKeyLen;
    if (EVP_PKEY_derive(kctx.get(), outKey, &ol) <= 0)     return ECC_ERR_KDF;
    return ECC_OK;
}

// ----- AES-256-GCM ----------------------------------------------------------
int AesGcmEnc(const unsigned char key[/*kAesKeyLen*/],
              const unsigned char iv[/*kGcmIvLen*/],
              const unsigned char* pt, size_t ptLen,
              std::vector<unsigned char>& ct,
              unsigned char tag[/*kGcmTagLen*/])
{
    CipPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return ECC_ERR_AES;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return ECC_ERR_AES;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)kGcmIvLen, nullptr) != 1)
        return ECC_ERR_AES;
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) != 1) return ECC_ERR_AES;

    ct.resize(ptLen);
    int ol = 0;
    if (ptLen > 0 && EVP_EncryptUpdate(ctx.get(), ct.data(), &ol, pt, (int)ptLen) != 1)
        return ECC_ERR_AES;
    int fl = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ct.data() + ol, &fl) != 1) return ECC_ERR_AES;
    ct.resize((size_t)(ol + fl));
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)kGcmTagLen, tag) != 1)
        return ECC_ERR_AES;
    return ECC_OK;
}

int AesGcmDec(const unsigned char key[/*kAesKeyLen*/],
              const unsigned char iv[/*kGcmIvLen*/],
              const unsigned char* ct, size_t ctLen,
              const unsigned char tag[/*kGcmTagLen*/],
              std::vector<unsigned char>& pt)
{
    CipPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return ECC_ERR_AES;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return ECC_ERR_AES;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)kGcmIvLen, nullptr) != 1)
        return ECC_ERR_AES;
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, iv) != 1) return ECC_ERR_AES;

    pt.resize(ctLen);
    int ol = 0;
    if (ctLen > 0 && EVP_DecryptUpdate(ctx.get(), pt.data(), &ol, ct, (int)ctLen) != 1)
        return ECC_ERR_AES;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)kGcmTagLen, (void*)tag) != 1)
        return ECC_ERR_AES;
    int fl = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), pt.data() + ol, &fl) != 1)
        return ECC_ERR_AES;     // tag mismatch -> tampered ciphertext
    pt.resize((size_t)(ol + fl));
    return ECC_OK;
}

int Sha256(const unsigned char* msg, size_t len, unsigned char out[/*32*/])
{
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) return ECC_ERR_INTERNAL;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) return ECC_ERR_INTERNAL;
    if (len > 0 && EVP_DigestUpdate(ctx.get(), msg, len) != 1)    return ECC_ERR_INTERNAL;
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out, &n) != 1)              return ECC_ERR_INTERNAL;
    return (n == 32) ? ECC_OK : ECC_ERR_INTERNAL;
}

} // namespace

// =============================================================================
// CEccModule
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

    ECGPtr group(EC_GROUP_new_by_curve_name(kCurveNid));
    if (!group) return ECC_ERR_KEYGEN;

    BNPtr order(BN_new());
    if (!order || EC_GROUP_get_order(group.get(), order.get(), nullptr) != 1)
        return ECC_ERR_KEYGEN;

    BNPtr d(BN_new());
    if (!d) return ECC_ERR_KEYGEN;
    int rc = GenScalar(m_pRng, order.get(), d.get());
    if (rc != ECC_OK) return rc;

    ECKPtr ec(MakeECKeyFromScalar(d.get(), group.get()));
    if (!ec) return ECC_ERR_KEYGEN;

    unsigned char pubBytes[kPointLen];
    rc = SerializePublicPoint(ec.get(), pubBytes);
    if (rc != ECC_OK) return rc;

    unsigned char privBytes[kScalarLen] = {0};
    int n = BN_num_bytes(d.get());
    if (n > (int)kScalarLen) return ECC_ERR_KEY_SERIALIZE;
    BN_bn2bin(d.get(), privBytes + (kScalarLen - (size_t)n));

    HexEncode(pubBytes, kPointLen, pchPubKey);
    HexEncode(privBytes, kScalarLen, pchPriKey);
    return ECC_OK;
}

int CEccModule::EncrptData(char* pchPubKey, char* pchPlain, char* pchEnc)
{
    if (!pchPubKey || !pchPlain || !pchEnc) return ECC_ERR_NULL_ARG;

    EVP_PKEY* rRaw = nullptr;
    int rc = LoadPublicKeyFromHex(pchPubKey, &rRaw);
    if (rc != ECC_OK) return rc;
    PKeyPtr recipient(rRaw);

    std::vector<unsigned char> plainBytes;
    rc = HexDecode(pchPlain, plainBytes);
    if (rc != ECC_OK) return rc;

    // Ephemeral keypair via our RNG.
    ECGPtr group(EC_GROUP_new_by_curve_name(kCurveNid));
    if (!group) return ECC_ERR_KEYGEN;
    BNPtr order(BN_new());
    if (!order || EC_GROUP_get_order(group.get(), order.get(), nullptr) != 1)
        return ECC_ERR_KEYGEN;
    BNPtr dEph(BN_new());
    if (!dEph) return ECC_ERR_KEYGEN;
    rc = GenScalar(m_pRng, order.get(), dEph.get());
    if (rc != ECC_OK) return rc;
    ECKPtr ephEc(MakeECKeyFromScalar(dEph.get(), group.get()));
    if (!ephEc) return ECC_ERR_KEYGEN;

    PKeyPtr ephPkey(EVP_PKEY_new());
    if (!ephPkey) return ECC_ERR_KEYGEN;
    if (EVP_PKEY_set1_EC_KEY(ephPkey.get(), ephEc.get()) != 1) return ECC_ERR_KEYGEN;

    unsigned char aesKey[kAesKeyLen];
    rc = DeriveSharedKey(ephPkey.get(), recipient.get(), aesKey);
    if (rc != ECC_OK) return rc;

    unsigned char iv[kGcmIvLen];
    rc = m_pRng->GenerateBytes(iv, kGcmIvLen);
    if (rc != ECC_OK) return rc;

    std::vector<unsigned char> ct;
    unsigned char tag[kGcmTagLen];
    rc = AesGcmEnc(aesKey, iv,
                   plainBytes.empty() ? nullptr : plainBytes.data(),
                   plainBytes.size(), ct, tag);
    if (rc != ECC_OK) return rc;

    unsigned char ephPubBytes[kPointLen];
    rc = SerializePublicPoint(ephEc.get(), ephPubBytes);
    if (rc != ECC_OK) return rc;

    // blob: ephPub(65) || iv(12) || tag(16) || ct
    size_t blobLen = kPointLen + kGcmIvLen + kGcmTagLen + ct.size();
    std::vector<unsigned char> blob(blobLen);
    size_t off = 0;
    std::memcpy(blob.data() + off, ephPubBytes, kPointLen);  off += kPointLen;
    std::memcpy(blob.data() + off, iv,          kGcmIvLen);  off += kGcmIvLen;
    std::memcpy(blob.data() + off, tag,         kGcmTagLen); off += kGcmTagLen;
    if (!ct.empty()) std::memcpy(blob.data() + off, ct.data(), ct.size());

    HexEncode(blob.data(), blob.size(), pchEnc);
    return ECC_OK;
}

int CEccModule::DecrptData(char* pchPriKey, char* pchEnc, char* pchPlain)
{
    if (!pchPriKey || !pchEnc || !pchPlain) return ECC_ERR_NULL_ARG;

    EVP_PKEY* pRaw = nullptr;
    int rc = LoadPrivateKeyFromHex(pchPriKey, &pRaw);
    if (rc != ECC_OK) return rc;
    PKeyPtr priv(pRaw);

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

    ECGPtr group(EC_GROUP_new_by_curve_name(kCurveNid));
    if (!group) return ECC_ERR_KEY_PARSE;
    ECKPtr ephEc(EC_KEY_new());
    if (!ephEc) return ECC_ERR_KEY_PARSE;
    if (EC_KEY_set_group(ephEc.get(), group.get()) != 1) return ECC_ERR_KEY_PARSE;
    ECPPtr Q(EC_POINT_new(group.get()));
    if (!Q) return ECC_ERR_KEY_PARSE;
    if (EC_POINT_oct2point(group.get(), Q.get(), ephPub, kPointLen, nullptr) != 1)
        return ECC_ERR_KEY_PARSE;
    if (EC_KEY_set_public_key(ephEc.get(), Q.get()) != 1) return ECC_ERR_KEY_PARSE;

    PKeyPtr ephPkey(EVP_PKEY_new());
    if (!ephPkey) return ECC_ERR_KEY_PARSE;
    if (EVP_PKEY_set1_EC_KEY(ephPkey.get(), ephEc.get()) != 1) return ECC_ERR_KEY_PARSE;

    unsigned char aesKey[kAesKeyLen];
    rc = DeriveSharedKey(priv.get(), ephPkey.get(), aesKey);
    if (rc != ECC_OK) return rc;

    std::vector<unsigned char> pt;
    rc = AesGcmDec(aesKey, iv, ct, ctLen, tag, pt);
    if (rc != ECC_OK) return rc;

    HexEncode(pt.data(), pt.size(), pchPlain);
    return ECC_OK;
}

int CEccModule::SignData(char* pchPriKey, char* pchPlain, char* pchSign)
{
    if (!pchPriKey || !pchPlain || !pchSign) return ECC_ERR_NULL_ARG;

    EVP_PKEY* pRaw = nullptr;
    int rc = LoadPrivateKeyFromHex(pchPriKey, &pRaw);
    if (rc != ECC_OK) return rc;
    PKeyPtr priv(pRaw);

    std::vector<unsigned char> msg;
    rc = HexDecode(pchPlain, msg);
    if (rc != ECC_OK) return rc;

    unsigned char hash[32];
    rc = Sha256(msg.empty() ? nullptr : msg.data(), msg.size(), hash);
    if (rc != ECC_OK) return rc;

    EC_KEY* ec = const_cast<EC_KEY*>(EVP_PKEY_get0_EC_KEY(priv.get()));
    if (!ec) return ECC_ERR_SIGN;
    SigPtr sig(ECDSA_do_sign(hash, (int)sizeof(hash), ec));
    if (!sig) return ECC_ERR_SIGN;

    const BIGNUM *r = nullptr, *s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    if (!r || !s) return ECC_ERR_SIGN;

    unsigned char rs[kSigRSLen] = {0};
    int rn = BN_num_bytes(r), sn = BN_num_bytes(s);
    if (rn > 32 || sn > 32) return ECC_ERR_SIGN;
    BN_bn2bin(r, rs + (32 - (size_t)rn));
    BN_bn2bin(s, rs + 32 + (32 - (size_t)sn));

    HexEncode(rs, kSigRSLen, pchSign);
    return ECC_OK;
}

int CEccModule::VerifyData(char* pchPubKey, char* pchPlain, char* pchSign)
{
    if (!pchPubKey || !pchPlain || !pchSign) return ECC_ERR_NULL_ARG;

    EVP_PKEY* pRaw = nullptr;
    int rc = LoadPublicKeyFromHex(pchPubKey, &pRaw);
    if (rc != ECC_OK) return rc;
    PKeyPtr pub(pRaw);

    std::vector<unsigned char> rs;
    rc = HexDecode(pchSign, rs);
    if (rc != ECC_OK) return rc;
    if (rs.size() != kSigRSLen) return ECC_ERR_VERIFY;

    std::vector<unsigned char> msg;
    rc = HexDecode(pchPlain, msg);
    if (rc != ECC_OK) return rc;

    unsigned char hash[32];
    rc = Sha256(msg.empty() ? nullptr : msg.data(), msg.size(), hash);
    if (rc != ECC_OK) return rc;

    SigPtr sig(ECDSA_SIG_new());
    if (!sig) return ECC_ERR_VERIFY;
    BIGNUM* rBN = BN_bin2bn(rs.data(),      32, nullptr);
    BIGNUM* sBN = BN_bin2bn(rs.data() + 32, 32, nullptr);
    if (!rBN || !sBN || ECDSA_SIG_set0(sig.get(), rBN, sBN) != 1) {
        if (rBN) BN_free(rBN);
        if (sBN) BN_free(sBN);
        return ECC_ERR_VERIFY;
    }
    // sig now owns rBN, sBN.

    EC_KEY* ec = const_cast<EC_KEY*>(EVP_PKEY_get0_EC_KEY(pub.get()));
    if (!ec) return ECC_ERR_VERIFY;
    int ok = ECDSA_do_verify(hash, (int)sizeof(hash), sig.get(), ec);
    return (ok == 1) ? ECC_OK : ECC_ERR_VERIFY;
}
