/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
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
 */

#ifndef HPKE_H_INCLUDED
#define HPKE_H_INCLUDED

#include <openssl/ssl.h>

/** default plaintext/ciphertext buffer size e.g. if processing stdin */
#ifndef HPKE_DEFSIZE
#define HPKE_DEFSIZE (40*1024)
#endif

/** biggest/default buffer for keys and internal buffers we use */
#ifndef HPKE_MAXSIZE
#define HPKE_MAXSIZE 2*1024 /* 2k is enough for anyone (using this program:-) */
#endif

/*
 * The HPKE modes
 */
#define HPKE_MODE_BASE              0 /**< Base mode  */
#define HPKE_MODE_PSK               1 /**< Pre-shared key mode */
#define HPKE_MODE_AUTH              2 /**< Authenticated mode */
#define HPKE_MODE_PSKAUTH           3 /**< PSK+authenticated mode */

/*
 * The (16bit) HPKE algorithn IDs
 */
#define HPKE_KEM_ID_RESERVED         0x0000 /**< not used */
#define HPKE_KEM_ID_P256             0x0010 /**< NIST P-256 */
#define HPKE_KEM_ID_P384             0x0011 /**< NIST P-256 */
#define HPKE_KEM_ID_P521             0x0012 /**< NIST P-521 */
#define HPKE_KEM_ID_25519            0x0020 /**< Curve25519 */
#define HPKE_KEM_ID_448              0x0021 /**< Curve448 */

#define HPKE_KDF_ID_RESERVED         0x0000 /**< not used */
#define HPKE_KDF_ID_HKDF_SHA256      0x0001 /**< HKDF-SHA256 */
#define HPKE_KDF_ID_HKDF_SHA384      0x0002 /**< HKDF-SHA512 */
#define HPKE_KDF_ID_HKDF_SHA512      0x0003 /**< HKDF-SHA512 */
#define HPKE_KDF_ID_MAX              0x0003 /**< HKDF-SHA512 */

#define HPKE_AEAD_ID_RESERVED        0x0000 /**< not used */
#define HPKE_AEAD_ID_AES_GCM_128     0x0001 /**< AES-GCM-128 */
#define HPKE_AEAD_ID_AES_GCM_256     0x0002 /**< AES-GCM-256 */
#define HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 /**< Chacha20-Poly1305 */
#define HPKE_AEAD_ID_MAX             0x0003 /**< Chacha20-Poly1305 */

/* strings for modes */
#define HPKE_MODESTR_BASE       "base"    /**< base mode (1), no sender auth */
#define HPKE_MODESTR_PSK        "psk"     /**< psk mode (2) */
#define HPKE_MODESTR_AUTH       "auth"    /**< auth (3), with a sender-key pair */
#define HPKE_MODESTR_PSKAUTH    "pskauth" /**< psk+sender-key pair (4) */

/* strings for suites */
#define HPKE_KEMSTR_P256        "p256"              /**< KEM id 0x10 */
#define HPKE_KEMSTR_P384        "p384"              /**< KEM id 0x11 */
#define HPKE_KEMSTR_P521        "p521"              /**< KEM id 0x12 */
#define HPKE_KEMSTR_X25519      "x25519"            /**< KEM id 0x20 */
#define HPKE_KEMSTR_X448        "x448"              /**< KEM id 0x21 */
#define HPKE_KDFSTR_256         "hkdf-sha256"       /**< KDF id 1 */
#define HPKE_KDFSTR_384         "hkdf-sha384"       /**< KDF id 2 */
#define HPKE_KDFSTR_512         "hkdf-sha512"       /**< KDF id 3 */
#define HPKE_AEADSTR_AES128GCM  "aes128gcm"         /**< AEAD id 1 */
#define HPKE_AEADSTR_AES256GCM  "aes256gcm"         /**< AEAD id 2 */
#define HPKE_AEADSTR_CP         "chachapoly1305"    /**< AEAD id 3 */

/*!
 * @brief ciphersuite combination
 */
typedef struct {
    uint16_t    kem_id; /**< Key Encryption Method id */
    uint16_t    kdf_id; /**< Key Derivation Function id */
    uint16_t    aead_id; /**< AEAD alg id */
} hpke_suite_t;

/*!
 * Two suite constants, use this like:
 *
 *          hpke_suite_t myvar = HPKE_SUITE_DEFAULT;
 */
#define HPKE_SUITE_DEFAULT \
    { HPKE_KEM_ID_25519, HPKE_KDF_ID_HKDF_SHA256, HPKE_AEAD_ID_AES_GCM_128 }
#define HPKE_SUITE_TURNITUPTO11 \
    { HPKE_KEM_ID_448, HPKE_KDF_ID_HKDF_SHA512, HPKE_AEAD_ID_CHACHA_POLY1305 }


/*
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output.
 *
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpub is the input buffer for sender public key
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int hpke_enc(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t authprivlen, unsigned char *authpriv, EVP_PKEY *authpriv_evp,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t *senderpublen, unsigned char *senderpub,
        size_t *cipherlen, unsigned char *cipher
#ifdef TESTVECTORS
        , void *tv
#endif
        );

/*
 * @brief HPKE encryption function, with externally supplied sender key pair
 *
 * This function is provided with an ECDH key pair that is used for
 * HPKE encryption.
 *
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param senderpublen length of the input buffer with the sender's public key
 * @param senderpub is the input buffer for sender public key
 * @param senderpriv has the handle for the sender private key
 * @param cipherlen length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int hpke_enc_evp(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t authprivlen, unsigned char *authpriv, EVP_PKEY *authpriv_evp,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t senderpublen, unsigned char *senderpub, EVP_PKEY *senderpriv,
        size_t *cipherlen, unsigned char *cipher
#ifdef TESTVECTORS
        , void *tv
#endif
        );

/*
 * @brief HPKE single-shot decryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public (authentication) key
 * @param pub is the encoded public (authentication) key
 * @param privlen is the length of the private key
 * @param priv is the encoded private key
 * @param evppriv is a pointer to an internal form of private key
 * @param enclen is the length of the peer's public value
 * @param enc is the peer's public value
 * @param cipherlen is the length of the ciphertext
 * @param cipher is the ciphertext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param clearlen length of the input buffer for cleartext
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_dec(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        EVP_PKEY *evppriv,
        size_t enclen, unsigned char *enc,
        size_t cipherlen, unsigned char *cipher,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t *clearlen, unsigned char *clear);

/*!
 * @brief generate a key pair
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_kg(
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        size_t *privlen, unsigned char *priv);

/*!
 * @brief generate a key pair but keep private inside API
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_kg_evp(
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        EVP_PKEY **priv);

/**
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_ah_decode(
        size_t ahlen,
        const char *ah,
        size_t *blen,
        unsigned char **buf);

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not-1 otherwise
 */
int hpke_suite_check(hpke_suite_t suite);

/*!
 * @brief: map a kem_id and a private key buffer into an EVP_PKEY
 *
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, otherwise failure
 *
 * Note that the buffer is expected to be some form of the PEM encoded
 * private key, but could still have the PEM header or not, and might
 * or might not be base64 encoded. We'll try handle all those options.
 */
int hpke_prbuf2evp(
        unsigned int kem_id,
        unsigned char *prbuf,
        size_t prbuf_len,
        unsigned char *pubuf,
        size_t pubuf_len,
        EVP_PKEY **priv);

/*!
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 *
 * As usual buffers are caller allocated and lengths on input are buffer size.
 *
 * @param suite-in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
int hpke_good4grease(
        hpke_suite_t *suite_in,
        hpke_suite_t suite,
        unsigned char *pub,
        size_t *pub_len,
        unsigned char *cipher,
        size_t cipher_len);

/*!
 * @brief map a string to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
int hpke_str2suite(char *str, hpke_suite_t *suite);

/*!
 * @brief tell the caller how big the cipertext will be
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 *
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
int hpke_expansion(hpke_suite_t suite,
        size_t clearlen,
        size_t *cipherlen);

/*!
 * @brief set a non-default OSSL_LIB_CTX if needed
 * @param ctx is the context to set
 * @return 1 for success, otherwise failure
 */
int hpke_setlibctx(OSSL_LIB_CTX *libctx);

#endif

