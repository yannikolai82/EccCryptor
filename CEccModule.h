#pragma once

#include <cstddef>

// ---- Return codes -----------------------------------------------------------
#define ECC_OK                      0
#define ECC_ERR_NULL_ARG           -1
#define ECC_ERR_KEYGEN             -2
#define ECC_ERR_KEY_PARSE          -3
#define ECC_ERR_KEY_SERIALIZE      -4
#define ECC_ERR_ECDH               -5
#define ECC_ERR_KDF                -6
#define ECC_ERR_AES                -7
#define ECC_ERR_HEX                -8
#define ECC_ERR_SIGN               -9
#define ECC_ERR_VERIFY            -10
#define ECC_ERR_BUFFER_TOO_SMALL  -11
#define ECC_ERR_INTERNAL          -12
#define ECC_ERR_RNG               -13

// ---- Fixed lengths (NIST P-256, hex-encoded uppercase) ----------------------
// Public key  = uncompressed point 04||X||Y (65 bytes) -> 130 hex chars + '\0'
// Private key = scalar d           (32 bytes)          ->  64 hex chars + '\0'
// Signature   = raw r||s           (64 bytes)          -> 128 hex chars + '\0'
// Ciphertext overhead = ephPub(65) + IV(12) + tag(16)  = 93 bytes
//                                                       -> 186 hex chars + '\0'
#define ECC_PUBKEY_HEX_LEN        131
#define ECC_PRIKEY_HEX_LEN         65
#define ECC_SIGN_HEX_LEN          129
#define ECC_ENC_OVERHEAD_HEX      187   // hex chars of overhead incl. terminator

// =============================================================================
// IEccRng - pluggable random number generator.
//
// The module owns no RNG by default but installs a CSPRNG (OpenSSL RAND_bytes)
// at construction. Call SetRng(myRng) to swap in your own; SetRng(nullptr)
// restores the default. The module never deletes the RNG you pass in.
// =============================================================================
class IEccRng
{
public:
    virtual ~IEccRng() {}
    // Fill 'pBuf' with 'nLen' cryptographically random bytes.
    // Return ECC_OK on success, ECC_ERR_RNG on failure.
    virtual int GenerateBytes(unsigned char* pBuf, std::size_t nLen) = 0;
};

// =============================================================================
// CEccModule - NIST P-256 keygen / ECIES enc-dec / ECDSA sign-verify.
//
// All char* parameters are null-terminated UPPERCASE hex strings.
// Caller allocates every output buffer; see ECC_*_LEN macros above.
//
// pchPlain is treated as a hex-encoded byte string: convert your real data to
// hex before calling EncrptData/SignData, and convert hex back to bytes after
// DecrptData.
// =============================================================================
class CEccModule
{
public:
    CEccModule();
    ~CEccModule();

    // Replace the RNG used for keygen, ephemeral keys, and AES-GCM IVs.
    // Pass nullptr to revert to the default OpenSSL CSPRNG.
    // Caller retains ownership of pRng.
    void SetRng(IEccRng* pRng);

    // pchPubKey: out, >= ECC_PUBKEY_HEX_LEN bytes
    // pchPriKey: out, >= ECC_PRIKEY_HEX_LEN bytes
    int GetKey(char* pchPubKey, char* pchPriKey);

    // pchPubKey: in  hex public key
    // pchPlain : in  hex plaintext
    // pchEnc   : out hex ciphertext, >= ECC_ENC_OVERHEAD_HEX + strlen(pchPlain)
    int EncrptData(char* pchPubKey, char* pchPlain, char* pchEnc);

    // pchPriKey: in  hex private key
    // pchEnc   : in  hex ciphertext produced by EncrptData
    // pchPlain : out hex plaintext, >= strlen(pchEnc) - ECC_ENC_OVERHEAD_HEX + 2
    int DecrptData(char* pchPriKey, char* pchEnc, char* pchPlain);

    // pchSign: out hex signature, >= ECC_SIGN_HEX_LEN bytes
    int SignData(char* pchPriKey, char* pchPlain, char* pchSign);

    // Returns ECC_OK on valid signature, ECC_ERR_VERIFY on mismatch.
    int VerifyData(char* pchPubKey, char* pchPlain, char* pchSign);

private:
    IEccRng* m_pRng; // not owned
};
