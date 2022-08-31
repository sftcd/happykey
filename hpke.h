/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file
 * APIs and data structures for HPKE (RFC9180).
 */

#ifndef OSSL_HPKE_H
# define OSSL_HPKE_H
# pragma once

# include <openssl/ssl.h>

# ifdef __cplusplus
extern "C" {
# endif

/*
 * The HPKE modes
 */
# define OSSL_HPKE_MODE_BASE              0 /**< Base mode  */
# define OSSL_HPKE_MODE_PSK               1 /**< Pre-shared key mode */
# define OSSL_HPKE_MODE_AUTH              2 /**< Authenticated mode */
# define OSSL_HPKE_MODE_PSKAUTH           3 /**< PSK+authenticated mode */

/*
 * The (16bit) HPKE algorithn IDs
 */
# define OSSL_HPKE_KEM_ID_RESERVED         0x0000 /**< not used */
# define OSSL_HPKE_KEM_ID_P256             0x0010 /**< NIST P-256 */
# define OSSL_HPKE_KEM_ID_P384             0x0011 /**< NIST P-256 */
# define OSSL_HPKE_KEM_ID_P521             0x0012 /**< NIST P-521 */
# define OSSL_HPKE_KEM_ID_25519            0x0020 /**< Curve25519 */
# define OSSL_HPKE_KEM_ID_448              0x0021 /**< Curve448 */

# define OSSL_HPKE_KDF_ID_RESERVED         0x0000 /**< not used */
# define OSSL_HPKE_KDF_ID_HKDF_SHA256      0x0001 /**< HKDF-SHA256 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA384      0x0002 /**< HKDF-SHA384 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA512      0x0003 /**< HKDF-SHA512 */

# define OSSL_HPKE_AEAD_ID_RESERVED        0x0000 /**< not used */
# define OSSL_HPKE_AEAD_ID_AES_GCM_128     0x0001 /**< AES-GCM-128 */
# define OSSL_HPKE_AEAD_ID_AES_GCM_256     0x0002 /**< AES-GCM-256 */
# define OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 /**< Chacha20-Poly1305 */
# define OSSL_HPKE_AEAD_ID_EXPORTONLY      0xFFFF /**< export-only fake ID */

/* strings for modes */
# define OSSL_HPKE_MODESTR_BASE       "base"    /**< base mode (1) */
# define OSSL_HPKE_MODESTR_PSK        "psk"     /**< psk mode (2) */
# define OSSL_HPKE_MODESTR_AUTH       "auth"    /**< sender-key pair auth (3) */
# define OSSL_HPKE_MODESTR_PSKAUTH    "pskauth" /**< psk+sender-key pair (4) */

/* strings for suite components - ideally these'd be defined elsewhere */
# define OSSL_HPKE_KEMSTR_P256        "P-256"              /**< KEM id 0x10 */
# define OSSL_HPKE_KEMSTR_P384        "P-384"              /**< KEM id 0x11 */
# define OSSL_HPKE_KEMSTR_P521        "P-521"              /**< KEM id 0x12 */
# define OSSL_HPKE_KEMSTR_X25519      SN_X25519            /**< KEM id 0x20 */
# define OSSL_HPKE_KEMSTR_X448        SN_X448              /**< KEM id 0x21 */
# define OSSL_HPKE_KDFSTR_256         "hkdf-sha256"        /**< KDF id 1 */
# define OSSL_HPKE_KDFSTR_384         "hkdf-sha384"        /**< KDF id 2 */
# define OSSL_HPKE_KDFSTR_512         "hkdf-sha512"        /**< KDF id 3 */
# define OSSL_HPKE_AEADSTR_AES128GCM  LN_aes_128_gcm       /**< AEAD id 1 */
# define OSSL_HPKE_AEADSTR_AES256GCM  LN_aes_256_gcm       /**< AEAD id 2 */
# define OSSL_HPKE_AEADSTR_CP         LN_chacha20_poly1305 /**< AEAD id 3 */

/**
 * @brief ciphersuite combination
 */
typedef struct {
    uint16_t    kem_id; /**< Key Encryption Method id */
    uint16_t    kdf_id; /**< Key Derivation Function id */
    uint16_t    aead_id; /**< AEAD alg id */
} OSSL_HPKE_SUITE;

/**
 * Suite constants, use this like:
 *          OSSL_HPKE_SUITE myvar = OSSL_HPKE_SUITE_DEFAULT;
 */
# define OSSL_HPKE_SUITE_DEFAULT \
    {\
        OSSL_HPKE_KEM_ID_25519, \
        OSSL_HPKE_KDF_ID_HKDF_SHA256, \
        OSSL_HPKE_AEAD_ID_AES_GCM_128 \
    }

/**
 * @brief opaque type for HPKE contexts
 */
typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;

/**
 * @brief contex creator
 * @param mode is the desired HPKE mode
 * @param suite specifies the KEM, KDF and AEAD to use
 * @param libctx is the context to use
 * @param propq is a properties string
 * @return pointer to new context or NULL if error
 */
OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite,
                                 OSSL_LIB_CTX *libctx, const char *propq);

/** 
 * @brief free up storage for a HPKE context
 * @param ctx is the pointer to be free'd (can be NULL)
 */
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);

/**
 * @brief set a PSK for an HPKE context
 * @param ctx is the pointer for the HPKE context
 * @param pskid is a string identifying the PSK
 * @param psk is the PSK buffer
 * @param psklen is the size of the PSK
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_psk(OSSL_HPKE_CTX *ctx,
                           const char *pskid,
                           const unsigned char *psk, size_t psklen);

/**
 * @brief set a private key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 *
 * If both octets and an EVP_PKEY are suppplied, the latter
 * will be preferred.
 */
int OSSL_HPKE_CTX_set1_auth_priv(OSSL_HPKE_CTX *ctx, EVP_PKEY *privp);

/**
 * @brief set a public key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param pubp is an EVP_PKEY form of the public key
 * @return 1 for success, 0 for error
 *
 * If both octets and an EVP_PKEY are suppplied, the latter
 * will be preferred.
 */
int OSSL_HPKE_CTX_set1_auth_pub(OSSL_HPKE_CTX *ctx, EVP_PKEY *pubp);

/**
 * @brief set a exporter length and context for HPKE 
 * @param ctx is the pointer for the HPKE context
 * @param exp_ctx is the exporter context octets
 * @param exp_ctxlen is the size of exp_ctx
 * @param explen is the desired exporter output size
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_exporter(OSSL_HPKE_CTX *ctx,
                                const unsigned char *exp_ctx, size_t exp_ctxlen,
                                size_t explen);

/**
 * @brief ask for the state of the sequence of seal/open calls
 * @param ctx is the pointer for the HPKE context
 * @return seq returns the positive integer sequence number
 * @return 1 for success, 0 for error
 *
 * The value returned is the most recent used when sealing
 * or opening (successfully)
 */
int OSSL_HPKE_CTX_get0_seq(OSSL_HPKE_CTX *ctx, unsigned int *seq);

/**
 * @brief sender seal function 
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @param exp is the exporter octets
 * @param explen is the size the above
 * @param pub is the recipient public key octets
 * @param publen is the size the above
 * @param recip is the EVP_PKEY form of recipient public value
 * @param info is the info parameter
 * @param infolen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @return 1 for success, 0 for error
 *
 * If both octets and an EVP_PKEY are suppplied, the latter
 * will be preferred.
 *
 * This can be called once, or multiple, times.
 */
int OSSL_HPKE_sender_seal(OSSL_HPKE_CTX *ctx,
                          unsigned char *enc, size_t *enclen,
                          unsigned char *ct, size_t *ctlen,
                          unsigned char *exp, size_t *explen,
                          unsigned char *pub, size_t publen,
                          const unsigned char *info, size_t infolen,
                          const unsigned char *aad, size_t aadlen,
                          const unsigned char *pt, size_t ptlen);

/**
 * @brief recipient open function 
 * @param ctx is the pointer for the HPKE context
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param exp is the exporter octets
 * @param explen is the size the above
 * @param recippriv is the EVP_PKEY form of recipient private value
 * @param info is the info parameter
 * @param infolen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @return 1 for success, 0 for error
 *
 * If both octets and an EVP_PKEY are suppplied, the latter
 * will be preferred.
 *
 * This can be called once, or multiple, times.
 */
int OSSL_HPKE_recipient_open(OSSL_HPKE_CTX *ctx,
                             unsigned char *pt, size_t *ptlen,
                             const unsigned char *enc, size_t enclen,
                             unsigned char *exp, size_t *explen,
                             EVP_PKEY *recippriv,
                             const unsigned char *info, size_t infolen,
                             const unsigned char *aad, size_t aadlen,
                             const unsigned char *ct, size_t ctlen);

/**
 * @brief sender export-only function 
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @param exp is the exporter octets
 * @param explen is the size the above
 * @param pub is the recipient public key octets
 * @param publen is the size the above
 * @param info is the key schedule info parameter
 * @param infolen is the size the above
 * @return 1 for success, 0 for error
 *
 * If both octets and an EVP_PKEY are suppplied, the latter
 * will be preferred.
 *
 * This can be called once, or multiple, times.
 */
int OSSL_HPKE_export_only_sender(OSSL_HPKE_CTX *ctx,
                                 unsigned char *enc, size_t *enclen,
                                 unsigned char *ct, size_t *ctlen,
                                 unsigned char *exp, size_t *explen,
                                 unsigned char *pub, size_t publen,
                                 const unsigned char *info, size_t infolen);

/**
 * @brief receiver export-only function 
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @param exp is the exporter octets
 * @param explen is the size the above
 * @param recippriv is the EVP_PKEY form of recipient private value
 * @param info is the key schedule info parameter
 * @param infolen is the size the above
 * @return 1 for success, 0 for error
 *
 * If both octets and an EVP_PKEY are suppplied, the latter
 * will be preferred.
 *
 * This can be called once, or multiple, times.
 */
int OSSL_HPKE_export_only_recip(OSSL_HPKE_CTX *ctx,
                                unsigned char *enc, size_t *enclen,
                                unsigned char *ct, size_t *ctlen,
                                unsigned char *exp, size_t *explen,
                                EVP_PKEY *recippriv,
                                const unsigned char *info, size_t infolen);

/**
 * @brief generate a key pair
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikm is IKM, if supplied
 * @param ikmlen is the length of IKM, if supplied
 * @param pub is the public value
 * @param publen is the size of the public key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for success, other for error (error returns can be non-zero)
 *
 * Used for entities that will later receive HPKE values to
 * decrypt. Only the KEM from the suite is significant here.
 * The ``pub` output will typically be published so that
 * others can encrypt to the private key holder using HPKE.
 * The ``priv`` output contains the raw private value and
 * hence is sensitive.
 */
int OSSL_HPKE_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                         unsigned int mode, OSSL_HPKE_SUITE suite,
                         const unsigned char *ikm, size_t ikmlen,
                         unsigned char *pub, size_t *publen,
                         EVP_PKEY **priv);

/**
 * @brief check if a suite is supported locally
 * @param suite is the suite to check
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);

/**
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param suite_in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_good4grease(OSSL_LIB_CTX *libctx, const char *propq,
                          OSSL_HPKE_SUITE *suite_in,
                          OSSL_HPKE_SUITE *suite,
                          unsigned char *pub,
                          size_t *pub_len,
                          unsigned char *cipher,
                          size_t cipher_len);

/**
 * @brief map a string to a HPKE suite
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 *
 * An example good string is "x25519,hkdf-sha256,aes-128-gcm"
 * Symbols are #define'd for the relevant labels, e.g.
 * OSSL_HPKE_KEMSTR_X25519. Numeric (decimal or hex) values with
 * the relevant IANA codepoint valus may also be used,
 * e.g., "0x20,1,1" represents the same suite as the first
 * example.
 */
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite);
 
/**
 * @brief tell the caller how big the cipertext will be
 * @param suite is the suite to be used
 * @param enclen points to what'll be enc length
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_expansion(OSSL_HPKE_SUITE suite,
                        size_t *enclen,
                        size_t clearlen,
                        size_t *cipherlen);

/* 
 * below are the existing enc/dec APIs that will likely be
 * dropped, once new ones work ok
 */

/**
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output that can be sent to
 * the relevant private key holder along with the ciphertext.
 *
 * Note that the sender's public value is an output here in contrast
 * to the case of OSSL_HPKE_enc_evp where the sender's public value
 * is an input (along with the sender's private value).
 *
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
 * @param psk is the psk
 * @param psklen is the psk length
 * @param pub is the encoded public key
 * @param publen is the length of the public key
 * @param authpriv is the encoded private (authentication) key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clear is the encoded cleartext
 * @param clearlen is the length of the cleartext
 * @param aad is the encoded additional data
 * @param aadlen is the length of the additional data
 * @param info is the encoded info data (can be NULL)
 * @param infolen is the length of the info data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param senderpub is the input buffer for sender public key
 * @param senderpublen length of the input buffer for sender's public key
 * @param cipher is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
# ifdef TESTVECTORS
int OSSL_HPKE_enc(OSSL_LIB_CTX *libctx, const char *propq,
                  unsigned int mode, OSSL_HPKE_SUITE suite,
                  const char *pskid,
                  const unsigned char *psk, size_t psklen,
                  const unsigned char *pub, size_t publen,
                  const unsigned char *authpriv, size_t authprivlen,
                  EVP_PKEY *authpriv_evp,
                  const unsigned char *clear, size_t clearlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *info, size_t infolen,
                  const unsigned char *seq, size_t seqlen,
                  unsigned char *senderpub,size_t *senderpublen,
                  unsigned char *cipher, size_t *cipherlen,
                  void *tv);
# else
int OSSL_HPKE_enc(OSSL_LIB_CTX *libctx, const char *propq,
                  unsigned int mode, OSSL_HPKE_SUITE suite,
                  const char *pskid,
                  const unsigned char *psk, size_t psklen,
                  const unsigned char *pub, size_t publen,
                  const unsigned char *authpriv, size_t authprivlen,
                  EVP_PKEY *authpriv_evp,
                  const unsigned char *clear, size_t clearlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *info, size_t infolen,
                  const unsigned char *seq, size_t seqlen,
                  unsigned char *senderpub,size_t *senderpublen,
                  unsigned char *cipher, size_t *cipherlen);
# endif

/**
 * @brief HPKE multi-shot encryption function
 *
 * This function generates a non-ephemeral ECDH value internally and
 * provides the public and private components as outputs. The public
 * part can be sent to the relevant private key holder along with the
 * ciphertext. The private part can be re-used in subequent calls.
 *
 * Note that the sender's public value is an input here (as is the
 * sender's private value), in contrast to the case of OSSL_HPKE_enc
 * where the sender's public value is an output.
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
 * @param psk is the psk
 * @param psklen is the psk length
 * @param pub is the encoded public key
 * @param publen is the length of the public key
 * @param authpriv is the encoded private (authentication) key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clear is the encoded cleartext
 * @param clearlen is the length of the cleartext
 * @param aad is the encoded additional data
 * @param aadlen is the length of the additional data
 * @param info is the encoded info data (can be NULL)
 * @param infolen is the length of the info data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param senderpub is the input buffer for sender public key
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpriv is the EVP_PKEY* form of sender key pair
 * @param cipher is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
# ifdef TESTVECTORS
int OSSL_HPKE_enc_evp(OSSL_LIB_CTX *libctx, const char *propq,
                      unsigned int mode, OSSL_HPKE_SUITE suite,
                      const char *pskid,
                      const unsigned char *psk, size_t psklen,
                      const unsigned char *pub, size_t publen,
                      const unsigned char *authpriv, size_t authprivlen,
                      EVP_PKEY *authpriv_evp,
                      const unsigned char *clear, size_t clearlen,
                      const unsigned char *aad, size_t aadlen,
                      const unsigned char *info, size_t infolen,
                      const unsigned char *seq, size_t seqlen,
                      const unsigned char *senderpub, size_t senderpublen,
                      EVP_PKEY *senderpriv,
                      unsigned char *cipher, size_t *cipherlen,
                      void *tv);
# else
int OSSL_HPKE_enc_evp(OSSL_LIB_CTX *libctx, const char *propq,
                      unsigned int mode, OSSL_HPKE_SUITE suite,
                      const char *pskid,
                      const unsigned char *psk, size_t psklen,
                      const unsigned char *pub, size_t publen,
                      const unsigned char *authpriv, size_t authprivlen,
                      EVP_PKEY *authpriv_evp,
                      const unsigned char *clear, size_t clearlen,
                      const unsigned char *aad, size_t aadlen,
                      const unsigned char *info, size_t infolen,
                      const unsigned char *seq, size_t seqlen,
                      const unsigned char *senderpub, size_t senderpublen,
                      EVP_PKEY *senderpriv,
                      unsigned char *cipher, size_t *cipherlen);
# endif

/**
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
 * @param psk is the psk
 * @param psklen is the psk length
 * @param pub is the encoded public (authentication) key
 * @param publen is the length of the public (authentication) key
 * @param priv is the encoded private key
 * @param privlen is the length of the private key
 * @param evppriv is a pointer to an internal form of private key
 * @param enc is the peer's public value
 * @param enclen is the length of the peer's public value
 * @param cipher is the ciphertext
 * @param cipherlen is the length of the ciphertext
 * @param aad is the encoded additional data
 * @param aadlen is the length of the additional data
 * @param info is the encoded info data (can be NULL)
 * @param infolen is the length of the info data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param clear is the encoded cleartext
 * @param clearlen length of the input buffer for cleartext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_dec(OSSL_LIB_CTX *libctx, const char *propq,
                  unsigned int mode, OSSL_HPKE_SUITE suite,
                  const char *pskid, const unsigned char *psk, size_t psklen,
                  const unsigned char *pub, size_t publen,
                  const unsigned char *priv, size_t privlen, EVP_PKEY *evppriv,
                  const unsigned char *enc, size_t enclen,
                  const unsigned char *cipher, size_t cipherlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *info, size_t infolen,
                  const unsigned char *seq, size_t seqlen,
                  unsigned char *clear, size_t *clearlen);

# ifdef __cplusplus
}
# endif
#endif
