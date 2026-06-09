/*
 * Minimal mbedTLS 2.28 configuration for CEccModule.
 *
 * Enables only what the ECIES + ECDSA pipeline on NIST P-256 needs:
 *   - BIGNUM, ECP (P-256 only), ECDH, ECDSA   (asymmetric)
 *   - AES + GCM                                (symmetric, with built-in MAC)
 *   - SHA-256, MD, HKDF                        (hash + key derivation)
 *   - ASN.1 parse/write, OID                   (required by ECDSA_C, MD_C checks
 *                                               even though we never serialize DER)
 *
 * Deliberately OMITTED:
 *   - ENTROPY_C, CTR_DRBG_C, HMAC_DRBG_C : the caller supplies an RNG via IEccRng.
 *   - SSL/TLS, X.509, RSA, DHM, PK        : not used.
 *   - FS_IO, NET_C, THREADING_C, TIMING_C : no filesystem / network / threads
 *                                           inside the library.
 *
 * This config is intentionally portable to Windows XP, modern Windows, Linux,
 * and macOS. No Windows-Vista-only APIs (BCrypt etc.) are reachable.
 */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ---------- System features ---------- */
#define MBEDTLS_HAVE_ASM            /* allow bignum inline assembly where compiler supports it */
#define MBEDTLS_AES_ROM_TABLES      /* AES tables in .rodata, no writable lookup arrays */

/* ---------- Modules used directly by CEccModule_mbedtls.cpp ---------- */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C            /* required by MBEDTLS_GCM_C check */

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NO_INTERNAL_RNG /* we feed our own RNG; skip ECP's internal DRBG */

#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDH_LEGACY_CONTEXT /* use legacy mbedtls_ecdh_compute_shared API */
#define MBEDTLS_ECDSA_C

#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C

/* ---------- Platform abstraction (required on Windows) ---------- */
#define MBEDTLS_PLATFORM_C          /* mandatory on Windows per check_config.h:30 */

/* ---------- Pulled in by check_config.h prerequisites ---------- */
#define MBEDTLS_ASN1_PARSE_C        /* required by MBEDTLS_ECDSA_C check */
#define MBEDTLS_ASN1_WRITE_C        /* required by MBEDTLS_ECDSA_C check */
#define MBEDTLS_OID_C               /* required by MBEDTLS_MD_C / SHA-256 metadata */

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
