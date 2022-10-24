/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* APIs and data structures for HPKE (RFC9180)  */
#ifndef OSSL_HPKE_H
# define OSSL_HPKE_H
# pragma once

# include <openssl/obj_mac.h>
# include <openssl/types.h>

/* HPKE modes */
# define OSSL_HPKE_MODE_BASE              0 /**< Base mode  */
# define OSSL_HPKE_MODE_PSK               1 /**< Pre-shared key mode */
# define OSSL_HPKE_MODE_AUTH              2 /**< Authenticated mode */
# define OSSL_HPKE_MODE_PSKAUTH           3 /**< PSK+authenticated mode */

#ifdef HAPPYKEY
/* strings for modes */
# define OSSL_HPKE_MODESTR_BASE       "base"    /**< base mode (1) */
# define OSSL_HPKE_MODESTR_PSK        "psk"     /**< psk mode (2) */
# define OSSL_HPKE_MODESTR_AUTH       "auth"    /**< sender-key pair auth (3) */
# define OSSL_HPKE_MODESTR_PSKAUTH    "pskauth" /**< psk+sender-key pair (4) */
#endif
/*
 * The (16bit) HPKE algorithn ID IANA codepoints
 * If/when new IANA codepoints are added there are tables in
 * crypto/hpke/hpke_util.c that must also be updated.
 */
# define OSSL_HPKE_KEM_ID_RESERVED         0x0000 /**< not used */
# define OSSL_HPKE_KEM_ID_P256             0x0010 /**< NIST P-256 */
# define OSSL_HPKE_KEM_ID_P384             0x0011 /**< NIST P-384 */
# define OSSL_HPKE_KEM_ID_P521             0x0012 /**< NIST P-521 */
# define OSSL_HPKE_KEM_ID_X25519           0x0020 /**< Curve25519 */
# define OSSL_HPKE_KEM_ID_X448             0x0021 /**< Curve448 */

# define OSSL_HPKE_KDF_ID_RESERVED         0x0000 /**< not used */
# define OSSL_HPKE_KDF_ID_HKDF_SHA256      0x0001 /**< HKDF-SHA256 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA384      0x0002 /**< HKDF-SHA384 */
# define OSSL_HPKE_KDF_ID_HKDF_SHA512      0x0003 /**< HKDF-SHA512 */

# define OSSL_HPKE_AEAD_ID_RESERVED        0x0000 /**< not used */
# define OSSL_HPKE_AEAD_ID_AES_GCM_128     0x0001 /**< AES-GCM-128 */
# define OSSL_HPKE_AEAD_ID_AES_GCM_256     0x0002 /**< AES-GCM-256 */
# define OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 0x0003 /**< Chacha20-Poly1305 */
# define OSSL_HPKE_AEAD_ID_EXPORTONLY      0xFFFF /**< export-only fake ID */

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
# define OSSL_HPKE_AEADSTR_EXP        "exporter"           /**< AEAD id 0xff */

typedef struct {
    uint16_t    kem_id; /**< Key Encapsulation Method id */
    uint16_t    kdf_id; /**< Key Derivation Function id */
    uint16_t    aead_id; /**< AEAD alg id */
} OSSL_HPKE_SUITE;

/**
 * Suite constants, use this like:
 *          OSSL_HPKE_SUITE myvar = OSSL_HPKE_SUITE_DEFAULT;
 */
# define OSSL_HPKE_SUITE_DEFAULT \
    {\
        OSSL_HPKE_KEM_ID_X25519, \
        OSSL_HPKE_KDF_ID_HKDF_SHA256, \
        OSSL_HPKE_AEAD_ID_AES_GCM_128 \
    }

typedef struct ossl_hpke_ctx_st OSSL_HPKE_CTX;

OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite,
                                 OSSL_LIB_CTX *libctx, const char *propq);
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);

int OSSL_HPKE_encap(OSSL_HPKE_CTX *ctx,
                    unsigned char *enc, size_t *enclen,
                    const unsigned char *pub, size_t publen,
                    const unsigned char *info, size_t infolen);
int OSSL_HPKE_seal(OSSL_HPKE_CTX *ctx,
                   unsigned char *ct, size_t *ctlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *pt, size_t ptlen);

int OSSL_HPKE_keygen(OSSL_HPKE_SUITE suite,
                     unsigned char *pub, size_t *publen, EVP_PKEY **priv,
                     const unsigned char *ikm, size_t ikmlen,
                     OSSL_LIB_CTX *libctx, const char *propq);
int OSSL_HPKE_decap(OSSL_HPKE_CTX *ctx,
                    const unsigned char *enc, size_t enclen,
                    EVP_PKEY *recippriv,
                    const unsigned char *info, size_t infolen);
int OSSL_HPKE_open(OSSL_HPKE_CTX *ctx,
                   unsigned char *pt, size_t *ptlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *ct, size_t ctlen);

int OSSL_HPKE_export(OSSL_HPKE_CTX *ctx,
                     unsigned char *secret,
                     size_t secretlen,
                     const unsigned char *label,
                     size_t labellen);

int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *priv);
int OSSL_HPKE_CTX_set1_authpub(OSSL_HPKE_CTX *ctx,
                               const unsigned char *pub,
                               size_t publen);
int OSSL_HPKE_CTX_set1_psk(OSSL_HPKE_CTX *ctx,
                           const char *pskid,
                           const unsigned char *psk, size_t psklen);

int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx,
                            const unsigned char *ikme, size_t ikmelen);

int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq);
int OSSL_HPKE_CTX_get_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq);

int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite);
int OSSL_HPKE_get_grease_value(OSSL_LIB_CTX *libctx, const char *propq,
                               OSSL_HPKE_SUITE *suite_in,
                               OSSL_HPKE_SUITE *suite,
                               unsigned char *enc,
                               size_t *enclen,
                               unsigned char *ct,
                               size_t ctlen);
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite);
size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen);
size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite);
size_t OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE suite);
# ifdef HAPPYKEY

/*
 * below are the old enc/dec APIs that now dropped from the
 * OpenSSL PR, but preserved here in case that's useful
 */

/**
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output that can be sent to
 * the relevant private key holder along with the ciphertext.
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
 * @param senderpriv is the sender's private key (if being re-used)
 * @param cipher is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
#  ifdef TESTVECTORS
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
                  unsigned char *senderpub, size_t *senderpublen,
                  EVP_PKEY *senderpriv,
                  unsigned char *cipher, size_t *cipherlen,
                  void *tv);
#  else
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
                  unsigned char *senderpub, size_t *senderpublen,
                  EVP_PKEY *senderpriv,
                  unsigned char *cipher, size_t *cipherlen);
#  endif

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
# endif

# ifdef HAPPYKEY
/**
 * @brief set a sender KEM private key for HPKE
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 *
 * If no key is set via this API an ephemeral one will be
 * generated in the first seal operation and used until the
 * context is free'd. (Or until a subsequent call to this
 * API replaces the key.) This suits senders who are typically
 * clients.
 */
int OSSL_HPKE_CTX_set1_senderpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *privp);
# endif
#endif
