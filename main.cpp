// Demo / smoke test for CEccModule (hex-string API).
//
// Build:
//   g++ -std=c++11 -O2 -Wno-deprecated-declarations CEccModule.cpp main.cpp -lcrypto -o ecc_demo

#include "CEccModule.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

// ---- Helpers for the demo: convert real ASCII text <-> hex string -----------
static void StrToHex(const char* s, char* out)
{
    static const char d[] = "0123456789ABCDEF";
    size_t i = 0;
    for (; s[i]; ++i) {
        unsigned char b = (unsigned char)s[i];
        out[2 * i]     = d[(b >> 4) & 0xF];
        out[2 * i + 1] = d[b & 0xF];
    }
    out[2 * i] = '\0';
}

static int Nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void HexToStr(const char* h, char* out)
{
    size_t n = std::strlen(h);
    for (size_t i = 0; i < n / 2; ++i)
        out[i] = (char)((Nib(h[2 * i]) << 4) | Nib(h[2 * i + 1]));
    out[n / 2] = '\0';
}

// ---- A trivial deterministic RNG to demonstrate SetRng ----------------------
class CSeedRng : public IEccRng
{
public:
    explicit CSeedRng(unsigned int seed) : m_state(seed ? seed : 1) {}
    int GenerateBytes(unsigned char* p, std::size_t n)
    {
        // xorshift32 — NOT secure; for unit-test reproducibility only.
        for (std::size_t i = 0; i < n; ++i) {
            m_state ^= m_state << 13;
            m_state ^= m_state >> 17;
            m_state ^= m_state << 5;
            p[i] = (unsigned char)(m_state & 0xFF);
        }
        return ECC_OK;
    }
private:
    unsigned int m_state;
};

// ---- Test driver ------------------------------------------------------------
int main()
{
    CEccModule ecc;

    char pub[ECC_PUBKEY_HEX_LEN] = {0};
    char pri[ECC_PRIKEY_HEX_LEN] = {0};

    // ---------- 1. GetKey ----------
    int rc = ecc.GetKey(pub, pri);
    if (rc != ECC_OK) { std::printf("GetKey FAILED rc=%d\n", rc); return 1; }
    std::printf("Public key  (%zu hex chars): %s\n", std::strlen(pub), pub);
    std::printf("Private key (%zu hex chars): %s\n\n", std::strlen(pri), pri);

    // Two consecutive calls must yield different keys (true RNG).
    char pub2[ECC_PUBKEY_HEX_LEN] = {0};
    char pri2[ECC_PRIKEY_HEX_LEN] = {0};
    ecc.GetKey(pub2, pri2);
    if (std::strcmp(pri, pri2) == 0) {
        std::printf("FAIL: two GetKey calls produced identical private keys\n");
        return 1;
    }
    std::printf("[OK] consecutive GetKey calls produce distinct keypairs\n\n");

    // ---------- 2. Encrypt / Decrypt round-trip ----------
    const char* msg = "Hello, ECC! Signed and encrypted via P-256 + ECIES + ECDSA.";
    char msgHex[1024] = {0};
    StrToHex(msg, msgHex);

    char enc[4096] = {0};
    rc = ecc.EncrptData(pub, msgHex, enc);
    if (rc != ECC_OK) { std::printf("EncrptData FAILED rc=%d\n", rc); return 1; }
    std::printf("Ciphertext (%zu hex chars):\n%s\n\n", std::strlen(enc), enc);

    char decHex[4096] = {0};
    rc = ecc.DecrptData(pri, enc, decHex);
    if (rc != ECC_OK) { std::printf("DecrptData FAILED rc=%d\n", rc); return 1; }

    char decStr[2048] = {0};
    HexToStr(decHex, decStr);
    std::printf("Decrypted text: %s\n", decStr);
    if (std::strcmp(msg, decStr) != 0) {
        std::printf("FAIL: round-trip mismatch\n");
        return 1;
    }
    std::printf("[OK] encrypt/decrypt round-trip\n\n");

    // Tampering the ciphertext must fail authentication.
    char encBad[4096] = {0};
    std::strcpy(encBad, enc);
    // Flip last hex nibble of ciphertext (well past the ephPub/iv/tag overhead).
    size_t L = std::strlen(encBad);
    encBad[L - 1] = (encBad[L - 1] == 'F') ? '0' : 'F';
    rc = ecc.DecrptData(pri, encBad, decHex);
    if (rc == ECC_OK) {
        std::printf("FAIL: tampered ciphertext accepted\n");
        return 1;
    }
    std::printf("[OK] tampered ciphertext rejected (rc=%d)\n\n", rc);

    // ---------- 3. Sign / Verify ----------
    char sig[ECC_SIGN_HEX_LEN] = {0};
    rc = ecc.SignData(pri, msgHex, sig);
    if (rc != ECC_OK) { std::printf("SignData FAILED rc=%d\n", rc); return 1; }
    std::printf("Signature (%zu hex chars): %s\n", std::strlen(sig), sig);

    rc = ecc.VerifyData(pub, msgHex, sig);
    if (rc != ECC_OK) { std::printf("FAIL: VerifyData on good msg rc=%d\n", rc); return 1; }
    std::printf("[OK] verify good message\n");

    char tampered[1024] = {0};
    StrToHex("Hello, ECC! Signed and encrypted via P-256 + ECIES + ECDSA?", tampered);
    rc = ecc.VerifyData(pub, tampered, sig);
    if (rc == ECC_OK) {
        std::printf("FAIL: tampered plaintext verified as valid\n");
        return 1;
    }
    std::printf("[OK] verify tampered message rejected (rc=%d)\n", rc);

    // Wrong key must also reject.
    rc = ecc.VerifyData(pub2, msgHex, sig);
    if (rc == ECC_OK) {
        std::printf("FAIL: signature verified under wrong public key\n");
        return 1;
    }
    std::printf("[OK] verify under wrong public key rejected (rc=%d)\n\n", rc);

    // ---------- 4. Pluggable RNG demo ----------
    CSeedRng seedA(0xCAFEBABE), seedB(0xCAFEBABE);
    char pa[ECC_PUBKEY_HEX_LEN] = {0}, paPri[ECC_PRIKEY_HEX_LEN] = {0};
    char pb[ECC_PUBKEY_HEX_LEN] = {0}, pbPri[ECC_PRIKEY_HEX_LEN] = {0};
    ecc.SetRng(&seedA);
    ecc.GetKey(pa, paPri);
    ecc.SetRng(&seedB);
    ecc.GetKey(pb, pbPri);
    if (std::strcmp(pa, pb) != 0 || std::strcmp(paPri, pbPri) != 0) {
        std::printf("FAIL: identically-seeded custom RNGs produced different keys\n");
        return 1;
    }
    std::printf("[OK] custom RNG is honored (identical seeds -> identical keys)\n");
    ecc.SetRng(nullptr); // restore default

    std::printf("\nAll tests passed.\n");
    return 0;
}
