/*
 * Copyright 2019 Stephen Farrell. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file 
 * This has the data structures and prototypes (both internal and external)
 * for an OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
 *
 * I plan to use this for my ESNI-enabled OpenSSL build when the time is 
 * right, that's: https://github.com/sftcd/openssl)
 */

#ifndef HPKE_H_INCLUDED
#define HPKE_H_INCLUDED

#ifdef TESTVECTORS
#include "hpketv.h"
#endif

/* biggest/default buffer we use */
#define HPKE_MAXSIZE (640*1024) ///< 640k is more than enough for anyone (using this program:-)

/*
 * The HPKE modes 
 * We only support base for now
 */
#define HPKE_MODE_BASE              0 ///< Base mode (all that we support for now)
#define HPKE_MODE_PSK               1 ///< Pre-shared key mode
#define HPKE_MODE_AUTH              2 ///< Authenticated mode
#define HPKE_MODE_PSK_AUTH          3 ///< PSK+authenticated mode

/*
 * The (16bit) HPKE algorithn IDs
 */
#define HPKE_KEM_ID_RESERVED         0x0000 ///< not used
#define HPKE_KEM_ID_P256             0x0001 ///< NIST P-256
#define HPKE_KEM_ID_25519            0x0002 ///< Curve25519
#define HPKE_KEM_ID_P521             0x0003 ///< NIST P-521
#define HPKE_KEM_ID_448              0x0004 ///< Curve448

#define HPKE_KDF_ID_RESERVED         0x0000 ///< not used
#define HPKE_KDF_ID_HKDF_SHA256      0x0001 ///< HKDF-SHA256
#define HPKE_KDF_ID_HKDF_SHA512      0x0002 ///< HKDF-SHA512

#define HPKE_AEAD_ID_RESERVED        0x0000 ///< not used
#define HPKE_AEAD_ID_AES_GCM_128     0x0001 ///< AES-GCM-128
#define HPKE_AEAD_ID_AES_GCM_256     0x0002 ///< AES-GCM-256
#define HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 ///< Chacha20-Poly1305

/*
 * @brief ciphersuite combination
 */
typedef struct {
    uint16_t    kem_id; ///< Key Encryption Method id
    uint16_t    kdf_id; ///< Key Derivation Function id
    uint16_t    aead_id; ///< Authenticated Encryption with Associated Data id
} hpke_suite_t;

/*
 * Some suite constants
 * Use this as follows:
 *
 *          hpke_suit_t myvar = HPKE_SUITE_DEFAULT;
 */
#define HPKE_SUITE_DEFAULT { HPKE_KEM_ID_25519, HPKE_KDF_ID_HKDF_SHA256, HPKE_AEAD_ID_AES_GCM_128 }

/**
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ahstr is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return zero for error, 1 for success 
 */
int hpke_ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf);

/*
 * @brief HPKE single-shot encryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param senderpublen is the length of the input buffer for the sender's public key (length used on output)
 * @param senderpub is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int hpke_enc(
        unsigned int mode,
        hpke_suite_t suite,
        size_t publen, 
        unsigned char *pub,
        size_t clearlen,
        unsigned char *clear,
        size_t aadlen,
        unsigned char *aad,
        size_t infolen,
        unsigned char *info,
        size_t *senderpublen,
        unsigned char *senderpub,
        size_t *cipherlen,
        unsigned char *cipher
#ifdef TESTVECTORS
        , hpke_tv_t *tv
#endif
        );

/*
 * @brief HPKE single-shot decryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param privlen is the length of the private key
 * @param priv is the encoded private key
 * @param cipherlen is the length of the ciphertext 
 * @param cipher is the ciphertext
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param clearlen is the length of the input buffer for cleartext (octets used on output)
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_dec(
        unsigned int mode,
        hpke_suite_t suite,
        size_t privlen, 
        unsigned char *priv,
        size_t cipherlen,
        unsigned char *cipher,
        size_t aadlen,
        unsigned char *aad,
        size_t *clearlen,
        unsigned char *clear);

#endif

