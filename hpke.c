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
 * An OpenSSL-based HPKE implementation of RFC9180
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#ifdef HAPPYKEY
/*
 * If we're building standalone (from github.com/sftcd/happykey) then
 * include the local header.
 */
#include "hpke.h"
/*
 * Define this if you want LOADS of printing of intermediate cryptographic values
 * Really only needed when new crypto added (hopefully)
 */
#undef SUPERVERBOSE
#ifdef TESTVECTORS
#include "hpketv.h"
#endif

#else /* For OpenSSL library */
#include <openssl/hpke.h>
#include <openssl/err.h>
#endif

/* constants defined in RFC9180 */
#define HPKE_VERLABEL        "HPKE-v1"  /**< version string label */
#define HPKE_SEC41LABEL      "KEM"      /**< "suite_id" label for 4.1 */
#define HPKE_SEC51LABEL      "HPKE"     /**< "suite_id" label for 5.1 */
#define HPKE_EAE_PRK_LABEL   "eae_prk"  /**< label in ExtractAndExpand */
#define HPKE_PSKIDHASH_LABEL "psk_id_hash"   /**< in key_schedule_context */
#define HPKE_INFOHASH_LABEL  "info_hash"     /**< in key_schedule_context */
#define HPKE_SS_LABEL        "shared_secret" /**< Yet another label */
#define HPKE_NONCE_LABEL     "base_nonce" /**< guess? */
#define HPKE_EXP_LABEL       "exp" /**< guess again? */
#define HPKE_KEY_LABEL       "key" /**< guess again? */
#define HPKE_PSK_HASH_LABEL  "psk_hash" /**< guess again? */
#define HPKE_SECRET_LABEL    "secret" /**< guess again? */

/* different RFC5869 "modes" used in RFC9180 */
#define HPKE_5869_MODE_PURE   0 /**< Do "pure" RFC5869 */
#define HPKE_5869_MODE_KEM    1 /**< Abide by HPKE section 4.1 */
#define HPKE_5869_MODE_FULL   2 /**< Abide by HPKE section 5.1 */

/* An internal max size, based on the extenal */
#define INT_MAXSIZE (4*HPKE_MAXSIZE)

/* max string len we'll try map to a suite */
#define HPKE_MAX_SUITESTR 38

/* "strength" input to RAND_bytes_ex */
#define HPKE_RSTRENGTH 10

/* an error macro just to make things easier */
#ifdef HAPPYKEY
#define HPKE_err { erv = __LINE__; goto err; }
#else
#define HPKE_err { \
    ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR); \
    erv = __LINE__; goto err; }
#endif
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
unsigned char *pbuf; /**< global var for debug printing */
size_t pblen = 1024; /**< global var for debug printing */

/*
 * @brief table of mode strings
 */
static const char *hpke_mode_strtab[] = {
    HPKE_MODESTR_BASE,
    HPKE_MODESTR_PSK,
    HPKE_MODESTR_AUTH,
    HPKE_MODESTR_PSKAUTH};
#endif

#ifdef HAPPYKEY
/*!
 * @brief  Map ascii to binary - utility macro used in >1 place
 */
#define HPKE_A2B(__c__) ( __c__ >= '0' && __c__ <= '9' ? (__c__ -'0' ) :\
                        ( __c__ >= 'A' && __c__ <= 'F' ? (__c__ -'A' + 10) :\
                        ( __c__ >= 'a' && __c__ <= 'f' ? (__c__ -'a' + 10) : 0)))
#endif
/*!
 * @brief info about an AEAD
 */
typedef struct {
    uint16_t            aead_id; /**< code point for aead alg */
    const EVP_CIPHER*   (*aead_init_func)(void); /**< the aead we're using */
    const char *name;   /* alg name */
    size_t              taglen; /**< aead tag len */
    size_t              Nk; /**< size of a key for this aead */
    size_t              Nn; /**< length of a nonce for this aead */
} hpke_aead_info_t;

/*!
 * @brief table of AEADs
 */
static hpke_aead_info_t hpke_aead_tab[] = {
    { 0, NULL, NULL, 0, 0, 0 }, /* treat 0 as error so nothing here */
    { HPKE_AEAD_ID_AES_GCM_128, EVP_aes_128_gcm, "AES-128-GCM", 16, 16, 12 },
    { HPKE_AEAD_ID_AES_GCM_256, EVP_aes_256_gcm, "AES-256-GCM", 16, 32, 12 },
#ifndef OPENSSL_NO_CHACHA20
# ifndef OPENSSL_NO_POLY1305
    { HPKE_AEAD_ID_CHACHA_POLY1305, EVP_chacha20_poly1305,
        "chacha20-poly1305", 16, 32, 12 }
# endif
#endif
};
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*
 * @brief table of AEAD strings
 */
static const char *hpke_aead_strtab[] = {
    NULL,
    HPKE_AEADSTR_AES128GCM,
    HPKE_AEADSTR_AES256GCM
#ifndef OPENSSL_NO_CHACHA20
#ifndef OPENSSL_NO_POLY1305
    ,HPKE_AEADSTR_CP
#endif
#endif
};
#endif

/*!
 * @brief info about a KEM
 */
typedef struct {
    uint16_t      kem_id; /**< code point for key encipherment method */
    const char    *keytype; /**< string form of algtype "EC"/"X25519"/"X448" */
    const char    *groupname; /**< string form of EC group for NIST curves  */
    int           groupid; /**< NID of KEM */
    const EVP_MD* (*hash_init_func)(void); /**< hash alg for the HKDF */
    size_t        Nsecret; /**< size of secrets */
    size_t        Nenc; /**< length of encapsulated key */
    size_t        Npk; /**< length of public key */
    size_t        Npriv; /**< length of raw private key */
} hpke_kem_info_t;

/*!
 * @brief table of KEMs
 */
static hpke_kem_info_t hpke_kem_tab[] = {
    { 0, NULL, NULL, 0, NULL, 0, 0, 0 }, /* treat 0 as error so nowt here */
    { HPKE_KEM_ID_P256, "EC", "P-256", NID_X9_62_prime256v1, EVP_sha256,
      32, 65, 65, 32 }, /* maybe "prime256v1" instead of P-256? */
    { HPKE_KEM_ID_P384, "EC", "P-384", NID_secp384r1, EVP_sha384,
      48, 97, 97, 48 },
    { HPKE_KEM_ID_P521, "EC", "P-521", NID_secp521r1, EVP_sha512,
      64, 133, 133, 66 },
    { HPKE_KEM_ID_25519, "X25519", NULL, EVP_PKEY_X25519, EVP_sha256,
      32, 32, 32, 32 },
    { HPKE_KEM_ID_448, "X448", NULL, EVP_PKEY_X448, EVP_sha512,
      64, 56, 56, 56 }
};
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*
 * @brief table of KEM strings
 *
 * Note: This also need blanks
 */
const char *hpke_kem_strtab[] = {
    NULL, 
    HPKE_KEMSTR_P256,
    HPKE_KEMSTR_P384,
    HPKE_KEMSTR_P521,
    HPKE_KEMSTR_X25519,
    HPKE_KEMSTR_X448 };
#endif

/*!
 * @brief info about a KDF
 */
typedef struct {
    uint16_t       kdf_id; /**< code point for KDF */
    const EVP_MD*  (*hash_init_func)(void); /**< the hash alg we're using */
    size_t         Nh; /**< length of hash/extract output */
} hpke_kdf_info_t;

/*!
 * @brief table of KDFs
 */
static hpke_kdf_info_t hpke_kdf_tab[] = {
    { 0, NULL, 0 }, /* keep indexing correct */
    { HPKE_KDF_ID_HKDF_SHA256, EVP_sha256, 32 },
    { HPKE_KDF_ID_HKDF_SHA384, EVP_sha384, 48 },
    { HPKE_KDF_ID_HKDF_SHA512, EVP_sha512, 64 }
};
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*
 * @brief table of KDF strings
 */
const char *hpke_kdf_strtab[] = {
    NULL,
    HPKE_KDFSTR_256,
    HPKE_KDFSTR_384,
    HPKE_KDFSTR_512};
#endif

/*!
 * @brief map from IANA codepoint to AEAD table index
 *
 * @param codepoint should be an IANA code point
 * @return index in AEAD table or 0 if error
 */
static uint16_t aead_iana2index(uint16_t codepoint)
{
    uint16_t naeads = sizeof(hpke_aead_tab) / sizeof(hpke_aead_info_t);
    uint16_t i = 0;

    /* why not be paranoid:-) */
    if ( ( sizeof(hpke_aead_tab) / sizeof(hpke_aead_info_t) ) > 65536  ) {
        return(0);
    }
    for (i=0; i != naeads; i++) {
        if (hpke_aead_tab[i].aead_id == codepoint) {
            return(i);
        }
    }
    return(0);
}

/*!
 * @brief map from IANA codepoint to KEM table index
 *
 * @param codepoint should be an IANA code point
 * @return index in KEM table or 0 if error
 */
static uint16_t kem_iana2index(uint16_t codepoint)
{
    uint16_t nkems = sizeof(hpke_kem_tab) / sizeof(hpke_kem_info_t);
    uint16_t i = 0;

    /* why not be paranoid:-) */
    if ( ( sizeof(hpke_kem_tab) / sizeof(hpke_kem_info_t) ) > 65536  ) {
        return(0);
    }
    for (i=0; i != nkems; i++) {
        if (hpke_kem_tab[i].kem_id == codepoint) {
            return(i);
        }
    }
    return(0);
}

/*!
 * @brief map from IANA codepoint to AEAD table index
 *
 * @param codepoint should be an IANA code point
 * @return index in AEAD table or 0 if error
 */
static uint16_t kdf_iana2index(uint16_t codepoint)
{
    uint16_t nkdfs = sizeof(hpke_kdf_tab) / sizeof(hpke_kdf_info_t);
    uint16_t i = 0;

    /* why not be paranoid:-) */
    if ( ( sizeof(hpke_kdf_tab) / sizeof(hpke_kdf_info_t) ) > 65536  ) {
        return(0);
    }
    for (i=0; i != nkdfs; i++) {
        if (hpke_kdf_tab[i].kdf_id == codepoint) {
            return(i);
        }
    }
    return(0);
}
#ifdef HAPPYKEY
/*!
 * <pre>
 * Since I always have to reconstruct this again in my head...
 * Bash command line hashing starting from ascii hex example:
 *
 *    $ echo -e "4f6465206f6e2061204772656369616e2055726e" | \
 *       xxd -r -p | openssl sha256
 *    (stdin)= 55c4040629c64c5efec2f7230407d612d16289d7c5d7afcf9340280abd2de1ab
 *
 * The above generates the Hash(info) used in Appendix A.2
 *
 * If you'd like to regenerate the zero_sha256 value above, feel free
 *    $ echo -n "" | openssl sha256
 *    echo -n "" | openssl sha256
 *    (stdin)= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 * Or if you'd like to re-caclulate the sha256 of nothing...
 *  SHA256_CTX sha256;
 *  SHA256_Init(&sha256);
 *  char* buffer = NULL;
 *  int bytesRead = 0;
 *  SHA256_Update(&sha256, buffer, bytesRead);
 *  SHA256_Final(zero_sha256, &sha256);
 * ...but I've done it for you, so no need:-)
 * static const unsigned char zero_sha256[SHA256_DIGEST_LENGTH] = {
 *     0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
 *     0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
 *     0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
 *     0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
 * </pre>
 */

/*!
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good otherwise bad
 */
static int hpke_ah_decode(
        size_t ahlen, const char *ah,
        size_t *blen, unsigned char **buf)
{
    size_t lblen = 0;
    int i = 0;
    int nibble = 0;
    unsigned char *lbuf = NULL;

    if (ahlen <= 0 || ah == NULL || blen == NULL || buf == NULL) {
        return 0;
    }
    if (ahlen % 2 == 1) {
        nibble = 1;
    }
    lblen = ahlen / 2 + nibble;
    lbuf = OPENSSL_malloc(lblen);
    if (lbuf == NULL) {
        return 0;
    }
    for (i = ahlen - 1; i > nibble ; i -= 2) {
        int j = i / 2;

        lbuf[j] = HPKE_A2B(ah[i-1]) * 16 + HPKE_A2B(ah[i]);
    }
    if (nibble) {
        lbuf[0] = HPKE_A2B(ah[0]);
    }
    *blen = lblen;
    *buf = lbuf;
    return 1;
}
#endif
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*!
 * @brief for odd/occasional debugging
 *
 * @param fout is a FILE * to use
 * @param msg is prepended to print
 * @param buf is the buffer to print
 * @param blen is the length of the buffer
 * @return 1 for success
 */
static int hpke_pbuf(FILE *fout, char *msg, unsigned char *buf, size_t blen)
{
    size_t i = 0;

    if (!fout) {
        return 0;
    }
    if (!msg) {
        fprintf(fout, "NULL msg:");
    } else {
        fprintf(fout, "%s (%lu): ", msg, blen);
    }
    if (!buf) {
        fprintf(fout, "buf is NULL, so probably something wrong\n");
        return 1;
    }
    if (blen == HPKE_MAXSIZE) {
        fprintf(fout, "length is HPKE_MAXSIZE, so probably unused\n");
        return 1;
    }
    if (blen == 0) {
        fprintf(fout, "length is 0, so probably something wrong\n");
        return 1;
    }
    for (i = 0; i < blen; i++) {
        fprintf(fout, "%02x", buf[i]);
    }
    fprintf(fout, "\n");
    return 1;
}
#endif

/*!
 * @brief Check if kem_id is ok/known to us
 * @param kem_id is the externally supplied kem_id
 * @return 1 for good, not 1 for error
 */
static int hpke_kem_id_check(uint16_t kem_id)
{
    switch (kem_id) {
        case HPKE_KEM_ID_P256:
        case HPKE_KEM_ID_P384:
        case HPKE_KEM_ID_P521:
        case HPKE_KEM_ID_25519:
        case HPKE_KEM_ID_448:
            break;
        default:
            return(__LINE__);
    }
    return(1);
}

/*!
 * @brief check if KEM uses NIST curve or not
 * @param kem_id is the externally supplied kem_id
 * @return 1 for NIST, 0 for good-but-non-NIST, other otherwise
 */
static int hpke_kem_id_nist_curve(uint16_t kem_id)
{
    if (hpke_kem_id_check(kem_id) != 1) return(__LINE__);
    if (kem_id >= 0x10 && kem_id < 0x20) return(1);
    return(0);
}

/*!
 * @brief hpke wrapper to import NIST curve public key as easily as x25519/x448
 *
 * @param libctx is the context to use (normally NULL)
 * @param curve is the curve NID
 * @param gname is the curve groupname
 * @param buf is the binary buffer with the (uncompressed) public value
 * @param buflen is the length of the private key buffer
 * @return a working EVP_PKEY * or NULL
 */
static EVP_PKEY* hpke_EVP_PKEY_new_raw_nist_public_key(
        OSSL_LIB_CTX *libctx,
        int curve,
        const char *gname,
        unsigned char *buf,
        size_t buflen)
{
    int erv = 1;
    EVP_PKEY *ret = NULL;
    /* following s3_lib.c:ssl_generate_param_group */
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx,
                "EC",NULL);
    if (cctx == NULL) {
        HPKE_err;
    }
    if (EVP_PKEY_paramgen_init(cctx) <= 0) {
        HPKE_err;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(cctx, curve) <= 0) {
        HPKE_err;
    }
    if (EVP_PKEY_paramgen(cctx, &ret) <= 0) {
        HPKE_err;
    }
    if (EVP_PKEY_set1_encoded_public_key(ret, buf, buflen) != 1) {
        if (ret) EVP_PKEY_free(ret);
        ret = NULL;
        HPKE_err;
    }

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    pblen = EVP_PKEY_get1_encoded_public_key(ret, &pbuf);
    hpke_pbuf(stdout, "EARLY public", pbuf, pblen);
    if (pblen) OPENSSL_free(pbuf);
#endif
    if (cctx) EVP_PKEY_CTX_free(cctx);
    if (erv == 1) return(ret);
    else return NULL;
}

/*
 * There's an odd accidental coding style feature here:
 * For all the externally visible functions in hpke.h, when
 * passing in a buffer, the length parameter precedes the
 * associated buffer pointer. It turns out that, entirely by
 * accident, I did the exact opposite for all the static
 * functions defined inside here. But since I was consistent
 * in both cases, I'll declare that a feature and move on:-)
 *
 * For example, just below you'll see:
 *          unsigned char *iv, size_t ivlen,
 * ...whereas in hpke.h, you see:
 *          size_t publen, unsigned char *pub,
 */

/*!
 * @brief do the AEAD decryption
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param cipher is obvious
 * @param cipherlen is the ciphertext length
 * @param plain is an output
 * @param plainlen input/output, better be big enough on input, exact on output
 * @return 1 for good otherwise bad
 */
static int hpke_aead_dec(
            OSSL_LIB_CTX  *libctx,
            hpke_suite_t  suite,
            unsigned char *key, size_t keylen,
            unsigned char *iv, size_t ivlen,
            unsigned char *aad, size_t aadlen,
            unsigned char *cipher, size_t cipherlen,
            unsigned char *plain, size_t *plainlen)
{
    int erv = 1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    size_t plaintextlen = 0;
    unsigned char *plaintext = NULL;
    size_t taglen;
    uint16_t aead_ind = 0;
    EVP_CIPHER *enc = NULL;

    aead_ind=aead_iana2index(suite.aead_id);
    if (aead_ind == 0 ) { HPKE_err; }
    taglen = hpke_aead_tab[aead_ind].taglen;
    plaintext = OPENSSL_malloc(cipherlen);
    if (plaintext == NULL) {
        HPKE_err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        HPKE_err;
    }
    /* Initialise the encryption operation */
    enc = EVP_CIPHER_fetch(libctx, hpke_aead_tab[aead_ind].name, NULL);
    if (enc == NULL) {
        HPKE_err;
    }
    if(1 != EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        HPKE_err;
    }
    EVP_CIPHER_free(enc); enc = NULL;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL)) {
        HPKE_err;
    }
    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))  {
        HPKE_err;
    }
    /* Provide AAD. Can be called zero or more times as required */
    if (aadlen != 0 && aad != NULL) {
        if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen)) {
            HPKE_err;
        }
    }
    /* 
     * Provide the message to be decrypted, and obtain cleartext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipherlen-taglen)) {
        HPKE_err;
    }
    plaintextlen = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx,
                EVP_CTRL_GCM_SET_TAG, taglen, cipher+cipherlen-taglen)) {
        HPKE_err;
    }
    /* Finalise decryption.  */
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)  {
        HPKE_err;
    }
    if (plaintextlen > *plainlen) {
        HPKE_err;
    }
    *plainlen = plaintextlen;
    memcpy(plain, plaintext, plaintextlen);

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (enc) EVP_CIPHER_free(enc);
    if (plaintext != NULL) OPENSSL_free(plaintext);
    return erv;
}

/*!
 * @brief do AEAD encryption as per the RFC
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param plain is an output
 * @param plainlen is the length of plain
 * @param cipher is an output
 * @param cipherlen input/output, better be big enough on input, exact on output
 * @return 1 for good otherwise bad
 */
static int hpke_aead_enc(
            OSSL_LIB_CTX  *libctx,
            hpke_suite_t  suite,
            unsigned char *key, size_t keylen,
            unsigned char *iv, size_t ivlen,
            unsigned char *aad, size_t aadlen,
            unsigned char *plain, size_t plainlen,
            unsigned char *cipher, size_t *cipherlen)
{
    int erv = 1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    size_t ciphertextlen;
    unsigned char *ciphertext = NULL;
    size_t taglen = 0;
    uint16_t aead_ind = 0;
    EVP_CIPHER *enc = NULL;
    unsigned char tag[16];

    aead_ind=aead_iana2index(suite.aead_id);
    if (aead_ind == 0 ) { HPKE_err; }
    taglen = hpke_aead_tab[aead_ind].taglen;
    if (taglen != 16) {
        HPKE_err;
    }
    if ((taglen + plainlen) > *cipherlen) {
        HPKE_err;
    }
    /*
     * Allocate this much extra for ciphertext and check the AEAD
     * doesn't require more - If it does, we'll fail.
     */
    ciphertext = OPENSSL_malloc(plainlen+taglen);
    if (ciphertext == NULL) {
        HPKE_err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        HPKE_err;
    }
    /* Initialise the encryption operation. */
    enc = EVP_CIPHER_fetch(libctx, hpke_aead_tab[aead_ind].name, NULL);
    if (enc == NULL) {
        HPKE_err;
    }
    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        HPKE_err;
    }
    EVP_CIPHER_free(enc); enc = NULL;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL)) {
        HPKE_err;
    }
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        HPKE_err;
    }
    /* 
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aadlen != 0 && aad != NULL) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen)) {
            HPKE_err;
        }
    }
    /* 
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plainlen)) {
        HPKE_err;
    }
    ciphertextlen = len;
    /* 
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        HPKE_err;
    }
    ciphertextlen += len;
    /*
     * Get the tag This isn't a duplicate so needs to be added to the ciphertext
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag)) {
        HPKE_err;
    }
    memcpy(ciphertext+ciphertextlen, tag, taglen);
    ciphertextlen += taglen;
    if (ciphertextlen > *cipherlen) {
        HPKE_err;
    }
    *cipherlen = ciphertextlen;
    memcpy(cipher, ciphertext, ciphertextlen);

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (enc) EVP_CIPHER_free(enc);
    if (ciphertext != NULL) OPENSSL_free(ciphertext);
    return erv;
}

/*!
 * @brief RFC5869 HKDF-Extract
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param mode5869 - controls labelling specifics
 * @param salt - surprisingly this is the salt;-)
 * @param saltlen - length of above
 * @param label - label for separation
 * @param labellen - length of above
 * @param zz - the initial key material (IKM)
 * @param zzlen - length of above
 * @param secret - the result of extraction (allocated inside)
 * @param secretlen - bufsize on input, used size on output
 * @return 1 for good otherwise bad
 *
 * Mode can be:
 * - HPKE_5869_MODE_PURE meaning to ignore all the
 *   HPKE-specific labelling and produce an output that's
 *   RFC5869 compliant (useful for testing and maybe
 *   more)
 * - HPKE_5869_MODE_KEM meaning to follow section 4.1
 *   where the suite_id is used as:
 *   concat("KEM", I2OSP(kem_id, 2))
 * - HPKE_5869_MODE_FULL meaning to follow section 5.1
 *   where the suite_id is used as:
 *     concat("HPKE", I2OSP(kem_id, 2),
 *          I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
 *
 * Isn't that a bit of a mess!
 */
static int hpke_extract(
        OSSL_LIB_CTX  *libctx,
        const hpke_suite_t suite, const int mode5869,
        const unsigned char *salt, const size_t saltlen,
        const char *label, const size_t labellen,
        const unsigned char *ikm, const size_t ikmlen,
        unsigned char *secret, size_t *secretlen)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;
    const char *mdname = NULL;
    unsigned char labeled_ikmbuf[INT_MAXSIZE];
    unsigned char *labeled_ikm = labeled_ikmbuf;
    size_t labeled_ikmlen = 0;
    int erv = 1;
    size_t concat_offset = 0;
    size_t lsecretlen = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {
        case HPKE_5869_MODE_PURE:
            labeled_ikmlen = ikmlen;
            labeled_ikm = (unsigned char*)ikm;
            break;

        case HPKE_5869_MODE_KEM:
            concat_offset = 0;
            memcpy(labeled_ikm, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset,
                    HPKE_SEC41LABEL, strlen(HPKE_SEC41LABEL));
            concat_offset += strlen(HPKE_SEC41LABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.kem_id % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset, ikm, ikmlen);
            concat_offset += ikmlen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikmlen = concat_offset;
            break;

        case HPKE_5869_MODE_FULL:
            concat_offset = 0;
            memcpy(labeled_ikm, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset,
                    HPKE_SEC51LABEL, strlen(HPKE_SEC51LABEL));
            concat_offset += strlen(HPKE_SEC51LABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.kem_id%256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.kdf_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.kdf_id%256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.aead_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.aead_id % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            if (ikmlen > 0) /* added 'cause asan test */
            memcpy(labeled_ikm + concat_offset, ikm, ikmlen);
            concat_offset += ikmlen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            labeled_ikmlen = concat_offset;
            break;
        default:
            HPKE_err;
    }

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(libctx, "hkdf", NULL)) == NULL) {
        HPKE_err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        HPKE_err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == HPKE_5869_MODE_KEM) {
        kem_ind=kem_iana2index(suite.kem_id);
        if (kem_ind == 0 ) { HPKE_err; }
        mdname = EVP_MD_get0_name(hpke_kem_tab[kem_ind].hash_init_func());
        if (!mdname) { HPKE_err; }
    } else {
        kdf_ind=kdf_iana2index(suite.kdf_id);
        if (kdf_ind == 0 ) { HPKE_err; }
        mdname = EVP_MD_get0_name(hpke_kdf_tab[kdf_ind].hash_init_func());
        if (!mdname) { HPKE_err; }
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (unsigned char*) labeled_ikm, labeled_ikmlen );
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            (unsigned char*) salt, saltlen);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        HPKE_err;
    }
    lsecretlen = EVP_KDF_CTX_get_kdf_size(kctx);
    if (lsecretlen > *secretlen) {
        HPKE_err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, secret, lsecretlen, params) <= 0) {
        HPKE_err;
    }
    EVP_KDF_CTX_free(kctx); kctx = NULL;
    *secretlen = lsecretlen;

err:
    if (kdf != NULL) EVP_KDF_free(kdf);
    if (kctx != NULL) EVP_KDF_CTX_free(kctx);
    memset(labeled_ikmbuf, 0, HPKE_MAXSIZE);
    return erv;
}


/*!
 * @brief RFC5869 HKDF-Expand
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param mode5869 - controls labelling specifics
 * @param prk - the initial pseudo-random key material
 * @param prk - length of above
 * @param label - label to prepend to info
 * @param labellen - label to prepend to info
 * @param context - the info
 * @param contextlen - length of above
 * @param L - the length of the output desired
 * @param out - the result of expansion (allocated by caller)
 * @param outlen - buf size on input
 * @return 1 for good otherwise bad
 */
static int hpke_expand(
                OSSL_LIB_CTX  *libctx,
                const hpke_suite_t suite, const int mode5869,
                const unsigned char *prk, const size_t prklen,
                const char *label, const size_t labellen,
                const unsigned char *info, const size_t infolen,
                const uint32_t L,
                unsigned char *out, size_t *outlen)
{
    int erv = 1;
    unsigned char libuf[INT_MAXSIZE];
    unsigned char *lip = libuf;
    size_t concat_offset = 0;
    size_t loutlen = L;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
    const char *mdname = NULL;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if (L > *outlen) {
        HPKE_err;
    }
    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {
        case HPKE_5869_MODE_PURE:
            if ((labellen+infolen) >= INT_MAXSIZE) { HPKE_err;}
            memcpy(lip, label, labellen);
            memcpy(lip + labellen, info, infolen);
            concat_offset = labellen + infolen;
            break;

        case HPKE_5869_MODE_KEM:
            lip[0] = (L / 256) % 256;
            lip[1] = L % 256;
            concat_offset = 2;
            memcpy(lip + concat_offset, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, HPKE_SEC41LABEL,
                    strlen(HPKE_SEC41LABEL));
            concat_offset += strlen(HPKE_SEC41LABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.kem_id % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, info, infolen);
            concat_offset += infolen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            break;

        case HPKE_5869_MODE_FULL:
            lip[0] = (L / 256) % 256;
            lip[1] = L % 256;
            concat_offset = 2;
            memcpy(lip + concat_offset, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, HPKE_SEC51LABEL,
                    strlen(HPKE_SEC51LABEL));
            concat_offset += strlen(HPKE_SEC51LABEL);
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.kem_id % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.kdf_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.kdf_id % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.aead_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.aead_id % 256;
            concat_offset += 1;
            memcpy(lip + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, info, infolen);
            concat_offset += infolen;
            if (concat_offset >= INT_MAXSIZE) { HPKE_err; }
            break;

        default:
            HPKE_err;
    }

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(libctx, "hkdf", NULL)) == NULL) {
        HPKE_err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        HPKE_err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == HPKE_5869_MODE_KEM) {
        kem_ind=kem_iana2index(suite.kem_id);
        if (kem_ind == 0 ) { HPKE_err; }
        mdname = EVP_MD_get0_name(hpke_kem_tab[kem_ind].hash_init_func());
        if (!mdname) { HPKE_err; }
    } else {
        kdf_ind=kdf_iana2index(suite.kdf_id);
        if (kdf_ind == 0 ) { HPKE_err; }
        mdname = EVP_MD_get0_name(hpke_kdf_tab[kdf_ind].hash_init_func());
        if (!mdname) { HPKE_err; }
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (unsigned char*) prk, prklen );
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            libuf, concat_offset);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        HPKE_err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, out, loutlen, params) <= 0) {
        HPKE_err;
    }
    EVP_KDF_CTX_free(kctx); kctx = NULL;
    *outlen = loutlen;

err:
    if (kdf != NULL) EVP_KDF_free(kdf);
    if (kctx != NULL) EVP_KDF_CTX_free(kctx);
    memset(libuf, 0, HPKE_MAXSIZE);
    return erv;
}

/*!
 * @brief ExtractAndExpand
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param mode5869 - controls labelling specifics
 * @param shared_secret - the initial DH shared secret
 * @param shared_secretlen - length of above
 * @param context - the info
 * @param contextlen - length of above
 * @param secret - the result of extract&expand
 * @param secretlen - buf size on input
 * @return 1 for good otherwise bad
 */
static int hpke_extract_and_expand(
                OSSL_LIB_CTX  *libctx,
                hpke_suite_t suite, int mode5869,
                unsigned char *shared_secret , size_t shared_secretlen,
                unsigned char *context, size_t contextlen,
                unsigned char *secret, size_t *secretlen
			)
{
	int erv = 1;
	unsigned char eae_prkbuf[HPKE_MAXSIZE];
    size_t eae_prklen = HPKE_MAXSIZE;
    size_t lsecretlen = 0;
    uint16_t kem_ind = 0;

    kem_ind=kem_iana2index(suite.kem_id);
    if (kem_ind == 0 ) { HPKE_err; }
    lsecretlen = hpke_kem_tab[kem_ind].Nsecret;
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\teae_ssinput", shared_secret, shared_secretlen);
    hpke_pbuf(stdout, "\teae_context", context, contextlen);
    printf("\tNsecret: %lu\n", lsecretlen);
#endif
	erv = hpke_extract(libctx, suite, mode5869,
            (const unsigned char*)"", 0,
            HPKE_EAE_PRK_LABEL, strlen(HPKE_EAE_PRK_LABEL),
			shared_secret, shared_secretlen,
			eae_prkbuf, &eae_prklen);
	if (erv != 1) { goto err; }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\teae_prk", eae_prkbuf, eae_prklen);
#endif
    erv = hpke_expand(libctx, suite, mode5869,
            eae_prkbuf, eae_prklen,
            HPKE_SS_LABEL, strlen(HPKE_SS_LABEL),
            context, contextlen,
            lsecretlen,
            secret, &lsecretlen);
	if (erv != 1) { goto err; }
    *secretlen = lsecretlen;
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tshared secret", secret, *secretlen);
#endif
err:
	memset(eae_prkbuf, 0, HPKE_MAXSIZE);
	return(erv);
}

#ifdef TESTVECTORS
/*!
 * @brief specific RFC5869 test for epxand/extract
 *
 * This uses the test vectors from https://tools.ietf.org/html/rfc5869
 * I added this as my expand is not agreeing with the HPKE test vectors.
 * All being well, this should be silent.
 *
 * @return 1 for good, otherwise bad
 */
static int hpke_test_expand_extract(void)
{
    /*
     * RFC 5869 Test Case 1:
     * Hash = SHA-256
     * IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
     * salt = 0x000102030405060708090a0b0c (13 octets)
     * info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
     * L    = 42
     *
     * PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
     *        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
     * OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
     *        2d2d0a90cf1a5a4c5db02d56ecc4c5bf
     *        34007208d5b887185865 (42 octets)
     */
    unsigned char IKM[22] = {0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b};
    size_t IKMlen = 22;
    unsigned char salt[13] = {0x00, 0x01, 0x02, 0x03,
                              0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b,
                              0x0c};
    size_t saltlen = 13;
    unsigned char info[10] = {0xf0, 0xf1, 0xf2, 0xf3,
                              0xf4, 0xf5, 0xf6, 0xf7,
                              0xf8, 0xf9};
    size_t infolen = 10;
    unsigned char PRK[32] = { 0x07, 0x77, 0x09, 0x36,
                              0x2c, 0x2e, 0x32, 0xdf,
                              0x0d, 0xdc, 0x3f, 0x0d,
                              0xc4, 0x7b, 0xba, 0x63,
                              0x90, 0xb6, 0xc7, 0x3b,
                              0xb5, 0x0f, 0x9c, 0x31,
                              0x22, 0xec, 0x84, 0x4a,
                              0xd7, 0xc2, 0xb3, 0xe5};
    unsigned char OKM[42] = { 0x3c, 0xb2, 0x5f, 0x25,
                              0xfa, 0xac, 0xd5, 0x7a,
                              0x90, 0x43, 0x4f, 0x64,
                              0xd0, 0x36, 0x2f, 0x2a,
                              0x2d, 0x2d, 0x0a, 0x90,
                              0xcf, 0x1a, 0x5a, 0x4c,
                              0x5d, 0xb0, 0x2d, 0x56,
                              0xec, 0xc4, 0xc5, 0xbf,
                              0x34, 0x00, 0x72, 0x08,
                              0xd5, 0xb8, 0x87, 0x18,
                              0x58, 0x65 }; /* 42 octets */
    size_t OKMlen = HPKE_MAXSIZE;
    unsigned char calc_prk[HPKE_MAXSIZE];
    size_t PRKlen = HPKE_MAXSIZE;
    unsigned char calc_okm[HPKE_MAXSIZE];
    int rv = 1;
    hpke_suite_t suite = HPKE_SUITE_DEFAULT;

    rv = hpke_extract(NULL, suite, HPKE_5869_MODE_PURE, salt, saltlen,
            "", 0, IKM, IKMlen, calc_prk, &PRKlen);
    if (rv != 1) {
        printf("rfc5869 check: hpke_extract failed: %d\n", rv);
        printf("rfc5869 check: hpke_extract failed: %d\n", rv);
        printf("rfc5869 check: hpke_extract failed: %d\n", rv);
        printf("rfc5869 check: hpke_extract failed: %d\n", rv);
        printf("rfc5869 check: hpke_extract failed: %d\n", rv);
        printf("rfc5869 check: hpke_extract failed: %d\n", rv);
    }
    if (memcmp(calc_prk, PRK, PRKlen)) {
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
    }
    OKMlen = 42;
    rv = hpke_expand(NULL, suite, HPKE_5869_MODE_PURE, PRK, PRKlen,
            (unsigned char*)"", 0, info, infolen, OKMlen, calc_okm, &OKMlen);
    if (rv != 1) {
        printf("rfc5869 check: hpke_expand failed: %d\n", rv);
        printf("rfc5869 check: hpke_expand failed: %d\n", rv);
        printf("rfc5869 check: hpke_expand failed: %d\n", rv);
        printf("rfc5869 check: hpke_expand failed: %d\n", rv);
        printf("rfc5869 check: hpke_expand failed: %d\n", rv);
        printf("rfc5869 check: hpke_expand failed: %d\n", rv);
    }
    if (memcmp(calc_okm, OKM, OKMlen)) {
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
    }
    return(rv);
}
#endif

/*!
 * @brief run the KEM with two keys as required
 *
 * @param libctx is the context to use (normally NULL)
 * @param encrypting is 1 if we're encrypting, 0 for decrypting
 * @param suite is the ciphersuite
 * @param key1 is the first key, for which we have the private value
 * @param key1enclen is the length of the encoded form of key1
 * @param key1en is the encoded form of key1
 * @param key2 is the peer's key
 * @param key2enclen is the length of the encoded form of key1
 * @param key2en is the encoded form of key1
 * @param akey is the authentication private key
 * @param apublen is the length of the encoded the authentication public key
 * @param apub is the encoded form of the authentication public key
 * @param ss is (a pointer to) the buffer for the shared secret result
 * @param sslen is the size of the buffer (octets-used on exit)
 * @return 1 for good, not 1 for not good
 */
static int hpke_do_kem(
        OSSL_LIB_CTX  *libctx,
        int encrypting, hpke_suite_t suite,
        EVP_PKEY *key1, size_t key1enclen, unsigned char *key1enc,
        EVP_PKEY *key2, size_t key2enclen, unsigned char *key2enc,
        EVP_PKEY *akey, size_t apublen, unsigned char *apub,
        unsigned char **ss, size_t *sslen)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    size_t zzlen = 2 * HPKE_MAXSIZE;
    unsigned char zz[2*HPKE_MAXSIZE];
    size_t kem_contextlen = HPKE_MAXSIZE;
    unsigned char kem_context[HPKE_MAXSIZE];
    size_t lsslen = HPKE_MAXSIZE;
    unsigned char lss[HPKE_MAXSIZE];

    /* step 2 run DH KEM to get zz */
    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, NULL);
    if (pctx == NULL) {
        HPKE_err;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        HPKE_err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0 ) {
        HPKE_err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &zzlen) <= 0) {
        HPKE_err;
    }
    if (zzlen >= HPKE_MAXSIZE) {
        HPKE_err;
    }
    if (EVP_PKEY_derive(pctx, zz, &zzlen) <= 0) {
        HPKE_err;
    }
    EVP_PKEY_CTX_free(pctx); pctx = NULL;

    kem_contextlen = key1enclen + key2enclen;
    if (kem_contextlen >= HPKE_MAXSIZE) {
        HPKE_err;
    }
    if (encrypting) {
        memcpy(kem_context, key1enc, key1enclen);
        memcpy(kem_context + key1enclen, key2enc, key2enclen);
    } else {
        memcpy(kem_context, key2enc, key2enclen);
        memcpy(kem_context + key2enclen, key1enc, key1enclen);
    }
    if (apublen != 0) {
        /* Append the public auth key (mypub) to kem_context */
        if ((kem_contextlen + apublen) >= HPKE_MAXSIZE) {
            HPKE_err;
        }
        memcpy(kem_context + kem_contextlen, apub, apublen);
        kem_contextlen += apublen;
    }

    if (akey != NULL) {
        size_t zzlen2 = 0;

        /* step 2 run to get 2nd half of zz */
        if (encrypting) {
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, akey, NULL);
        } else {
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, NULL);
        }
        if (pctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_derive_init(pctx) <= 0 ) {
            HPKE_err;
        }
        if (encrypting) {
            if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0 ) {
                HPKE_err;
            }
        } else {
            if (EVP_PKEY_derive_set_peer(pctx, akey) <= 0 ) {
                HPKE_err;
            }
        }
        if (EVP_PKEY_derive(pctx, NULL, &zzlen2) <= 0) {
            HPKE_err;
        }
        if (zzlen2 >= HPKE_MAXSIZE) {
            HPKE_err;
        }
        if (EVP_PKEY_derive(pctx, zz+zzlen, &zzlen2) <= 0) {
            HPKE_err;
        }
        zzlen += zzlen2;
        EVP_PKEY_CTX_free(pctx); pctx = NULL;
    }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tkem_context", kem_context, kem_contextlen);
    hpke_pbuf(stdout, "\tzz", zz, zzlen);
#endif
    erv = hpke_extract_and_expand(libctx, suite, HPKE_5869_MODE_KEM,
            zz, zzlen, kem_context, kem_contextlen, lss, &lsslen);
    if (erv != 1) { goto err; }
    *ss = OPENSSL_malloc(lsslen);
    if (*ss == NULL) {
        HPKE_err;
    }
    memcpy(*ss, lss, lsslen);
    *sslen = lsslen;

err:
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    return erv;
}


/*!
 * @brief check mode is in-range and supported
 * @param mode is the caller's chosen mode
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_mode_check(unsigned int mode)
{
    switch (mode) {
        case HPKE_MODE_BASE:
        case HPKE_MODE_PSK:
        case HPKE_MODE_AUTH:
        case HPKE_MODE_PSKAUTH:
            break;
        default:
            return(__LINE__);
    }
    return (1);
}

/*!
 * @brief check psk params are as per spec
 * @param mode is the mode in use
 * @param pskid PSK identifier
 * @param psklen length of PSK
 * @param psk the psk itself
 * @return 1 for good (OpenSSL style), not 1 for error
 *
 * If a PSK mode is used both pskid and psk must be
 * non-default. Otherwise we ignore the PSK params.
 */
static int hpke_psk_check(
        unsigned int mode,
        char *pskid,
        size_t psklen,
        unsigned char *psk)
{
    if (mode == HPKE_MODE_BASE || mode == HPKE_MODE_AUTH) return(1);
    if (pskid == NULL) return(__LINE__);
    if (psklen == 0) return(__LINE__);
    if (psk == NULL) return(__LINE__);
    return(1);
}

/*!
 * @brief map a kem_id and a private key buffer into an EVP_PKEY
 *
 * Note that the buffer is expected to be some form of the encoded
 * private key, and could still have the PEM header or not, and might
 * or might not be base64 encoded. We'll try handle all those options.
 *
 * @param libctx is the context to use (normally NULL)
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, otherwise failure
 */
static int hpke_prbuf2evp(
        OSSL_LIB_CTX  *libctx,
        unsigned int kem_id,
        unsigned char *prbuf,
        size_t prbuf_len,
        unsigned char *pubuf,
        size_t pubuf_len,
        EVP_PKEY **retpriv)
{
    int erv = 1;
    EVP_PKEY *lpriv = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *priv = NULL;
    const char *keytype = NULL;
    const char *groupname = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    uint16_t kem_ind = 0;

    if (hpke_kem_id_check(kem_id) != 1) { HPKE_err; }
    kem_ind=kem_iana2index(kem_id);
    if (kem_ind == 0 ) { HPKE_err; }
    keytype = hpke_kem_tab[kem_ind].keytype;
    groupname = hpke_kem_tab[kem_ind].groupname;
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("Called hpke_prbuf2evp with kem id: %04x\n", kem_id);
    hpke_pbuf(stdout, "hpke_prbuf2evp priv input", prbuf, prbuf_len);
    hpke_pbuf(stdout, "hpke_prbuf2evp pub input", pubuf, pubuf_len);
#endif
    if (prbuf == NULL || prbuf_len == 0 || retpriv == NULL) { HPKE_err; }
    if (hpke_kem_tab[kem_ind].Npriv == prbuf_len) {
        if (!keytype) { HPKE_err; }
        param_bld = OSSL_PARAM_BLD_new();
        if (!param_bld) { HPKE_err; }
        if (groupname != NULL &&
            OSSL_PARAM_BLD_push_utf8_string(param_bld,
                "group", groupname, 0) != 1) {
            HPKE_err;
        }
        if (pubuf && pubuf_len > 0) {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld,
                        "pub", pubuf, pubuf_len) != 1) {
                HPKE_err;
            }
        }
        if (strlen(keytype) == 2 && !strcmp(keytype, "EC")) {
            priv = BN_bin2bn(prbuf, prbuf_len, NULL);
            if (!priv) {
                HPKE_err;
            }
            if (OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv) != 1) {
                HPKE_err;
            }
        } else {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld,
                        "priv", prbuf, prbuf_len) != 1) {
                HPKE_err;
            }
        }
        params = OSSL_PARAM_BLD_to_param(param_bld);
        if (!params) {
            HPKE_err;
        }
        ctx = EVP_PKEY_CTX_new_from_name(libctx, keytype, NULL);
        if (ctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_fromdata_init(ctx) <= 0) {
            HPKE_err;
        }
        if (EVP_PKEY_fromdata(ctx, &lpriv, EVP_PKEY_KEYPAIR, params) <= 0) {
            HPKE_err;
        }
    }
    if (!lpriv) {
        /* check PEM decode - that might work :-) */
        BIO *bfp = BIO_new(BIO_s_mem());
        if (!bfp) { HPKE_err; }
        BIO_write(bfp, prbuf, prbuf_len);
        if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
            BIO_free_all(bfp); bfp = NULL;
            HPKE_err;
        }
        if (bfp != NULL) {
            BIO_free_all(bfp); bfp = NULL;
        }
        if (!lpriv) {
            /* if not done, prepend/append PEM header/footer and try again */
            unsigned char hf_prbuf[HPKE_MAXSIZE];
            size_t hf_prbuf_len = 0;
#define PEM_PRIVATEHEADER "-----BEGIN PRIVATE KEY-----\n"
#define PEM_PRIVATEFOOTER "\n-----END PRIVATE KEY-----\n"
            memcpy(hf_prbuf, PEM_PRIVATEHEADER, strlen(PEM_PRIVATEHEADER));
            hf_prbuf_len += strlen(PEM_PRIVATEHEADER);
            memcpy(hf_prbuf + hf_prbuf_len, prbuf, prbuf_len);
            hf_prbuf_len += prbuf_len;
            memcpy(hf_prbuf + hf_prbuf_len, PEM_PRIVATEFOOTER,
                    strlen(PEM_PRIVATEFOOTER));
            hf_prbuf_len += strlen(PEM_PRIVATEFOOTER);
            bfp = BIO_new(BIO_s_mem());
            if (!bfp) { HPKE_err; }
            BIO_write(bfp, hf_prbuf, hf_prbuf_len);
            if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
                BIO_free_all(bfp); bfp = NULL;
                HPKE_err;
            }
            if (bfp != NULL) {
                BIO_free_all(bfp); bfp = NULL;
            }
        }
    }
    if (!lpriv) { HPKE_err; }
    *retpriv = lpriv;
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("hpke_prbuf2evp success\n");
#endif
    if (priv) BN_free(priv);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (params) OSSL_PARAM_free(params);
    return(erv);

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("hpke_prbuf2evp FAILED at %d\n", erv);
#endif
    if (priv) BN_free(priv);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (params) OSSL_PARAM_free(params);
    return(erv);
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not 1 otherwise
 */
static int hpke_suite_check(hpke_suite_t suite)
{
    /*
     * Check that the fields of the suite are each
     * implemented here
     */
    int kem_ok = 0;
    int kdf_ok = 0;
    int aead_ok = 0;
    int ind = 0;
    int nkems = sizeof(hpke_kem_tab) / sizeof(hpke_kem_info_t);
    int nkdfs = sizeof(hpke_kdf_tab) / sizeof(hpke_kdf_info_t);
    int naeads = sizeof(hpke_aead_tab) / sizeof(hpke_aead_info_t);

    /* check KEM */
    for (ind = 0; ind != nkems; ind++) {
        if (suite.kem_id == hpke_kem_tab[ind].kem_id &&
            hpke_kem_tab[ind].hash_init_func != NULL) {
            kem_ok = 1;
            break;
        }
    }

    /* check kdf */
    for (ind = 0; ind != nkdfs; ind++) {
        if (suite.kdf_id == hpke_kdf_tab[ind].kdf_id &&
            hpke_kdf_tab[ind].hash_init_func != NULL) {
            kdf_ok = 1;
            break;
        }
    }

    /* check aead */
    for (ind = 0; ind != naeads; ind++) {
        if (suite.aead_id == hpke_aead_tab[ind].aead_id &&
            hpke_aead_tab[ind].aead_init_func != NULL) {
            aead_ok = 1;
            break;
        }
    }

    if (kem_ok == 1 && kdf_ok == 1 && aead_ok == 1) return(1);
    return(__LINE__);
}

/*!
 * @brief Internal HPKE single-shot encryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the recipient public key
 * @param pub is the encoded recipient public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the lenght of the additional data (can be zero)
 * @param aad is the encoded additional data (can be NULL)
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param extsenderpublen length of the input buffer for sender's public key
 * @param extsenderpub is the input buffer for sender public key
 * @param extsenderpriv has the handle for the sender private key
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpub is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_enc_int(
        OSSL_LIB_CTX  *libctx,
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t authprivlen, unsigned char *authpriv, EVP_PKEY* authpriv_evp,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t extsenderpublen, unsigned char *extsenderpub,
        EVP_PKEY *extsenderpriv,
        size_t rawsenderprivlen,  unsigned char *rawsenderpriv,
        size_t *senderpublen, unsigned char *senderpub,
        size_t *cipherlen, unsigned char *cipher
#ifdef TESTVECTORS
        , void *tv
#endif
        )

{
    int erv = 1; /* Our error return value - 1 is success */
    int crv = 1;
    int arv = 1;
    int evpcaller = 0;
    int rawcaller = 0;
#if defined(TESTVECTORS)
    hpke_tv_t *ltv = (hpke_tv_t*)tv;
#endif
    /* declare vars - done early so goto err works ok */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *skI = NULL;
    size_t  shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t  enclen = 0;
    unsigned char *enc = NULL;
    size_t  ks_contextlen = HPKE_MAXSIZE;
    unsigned char ks_context[HPKE_MAXSIZE];
    size_t  secretlen = HPKE_MAXSIZE;
    unsigned char secret[HPKE_MAXSIZE];
    size_t  psk_hashlen = HPKE_MAXSIZE;
    unsigned char psk_hash[HPKE_MAXSIZE];
    size_t  noncelen = HPKE_MAXSIZE;
    unsigned char nonce[HPKE_MAXSIZE];
    size_t  keylen = HPKE_MAXSIZE;
    unsigned char key[HPKE_MAXSIZE];
    size_t  exporterlen = HPKE_MAXSIZE;
    unsigned char exporter[HPKE_MAXSIZE];
    size_t  mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;
    uint16_t aead_ind = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if ((crv = hpke_mode_check(mode)) != 1) return(crv);
    if ((crv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) return(crv);
    if ((crv = hpke_suite_check(suite)) != 1) return(crv);
    /*
     * Depending on who called us, we may want to generate this key pair
     * or we may have had it handed to us via extsender* inputs
     */
    if (extsenderpublen > 0 && extsenderpub != NULL && extsenderpriv != NULL) {
        evpcaller = 1;
    }
    if (extsenderpublen > 0 && extsenderpub != NULL &&
            extsenderpriv == NULL && rawsenderprivlen > 0 &&
            rawsenderpriv != NULL) {
        rawcaller = 1;
    }
    if (!evpcaller && !rawcaller &&
        (!pub || !clear || !senderpublen || !senderpub ||
         !cipherlen  || !cipher)) return(__LINE__);
    if (evpcaller &&
        (!pub || !clear || !extsenderpublen || !extsenderpub ||
         !extsenderpriv || !cipherlen  || !cipher)) return(__LINE__);
    if (rawcaller &&
        (!pub || !clear || !extsenderpublen || !extsenderpub ||
         !rawsenderpriv || !cipherlen  || !cipher)) return(__LINE__);
    if ((mode == HPKE_MODE_AUTH || mode == HPKE_MODE_PSKAUTH) &&
        ((!authpriv || authprivlen == 0) && (!authpriv_evp))) return(__LINE__);
    if ((mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH) &&
        (!psk || psklen == 0 || !pskid)) return(__LINE__);
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("Encrypting:\n");
#endif

    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. generate sender's key pair
     * 2. run DH KEM to get dh
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD
     *
     * We'll follow the names used in the test vectors from the draft.
     * For now, we're replicating the setup from Appendix A.2
     */

    /* step 0. Initialise peer's key from string */
    kem_ind=kem_iana2index(suite.kem_id);
    if (kem_ind == 0 ) { HPKE_err; }
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkR = hpke_EVP_PKEY_new_raw_nist_public_key(libctx,
                hpke_kem_tab[kem_ind].groupid, 
                hpke_kem_tab[kem_ind].groupname, 
                pub, publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key_ex(libctx,
                hpke_kem_tab[kem_ind].keytype, NULL, pub, publen);
    }
    if (pkR == NULL) {
        HPKE_err;
    }

    /* step 1. generate or import sender's key pair: skE, pkE */
    if (!evpcaller && !rawcaller) {
        pctx = EVP_PKEY_CTX_new(pkR, NULL);
        if (pctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            HPKE_err;
        }
#ifdef TESTVECTORS
        if (ltv) {
            /*
            * Read encap DH private from tv, then use that instead of
            * a newly generated key pair
            */
            unsigned char *bin_skE = NULL; size_t bin_skElen = 0;
            unsigned char *bin_pkE = NULL; size_t bin_pkElen = 0;

            if (hpke_kem_id_check(ltv->kem_id) != 1) return(__LINE__);
            if (1 != hpke_ah_decode(strlen(ltv->skEm), ltv->skEm,
                        &bin_skElen, &bin_skE)) {
                HPKE_err;
            }
            if (1 != hpke_ah_decode(strlen(ltv->pkEm), ltv->pkEm,
                        &bin_pkElen, &bin_pkE)) {
                OPENSSL_free(bin_skE);
                HPKE_err;
            }
            if (hpke_prbuf2evp(libctx, ltv->kem_id, bin_skE, bin_skElen,
                        bin_pkE, bin_pkElen, &pkE) != 1) {
                OPENSSL_free(bin_skE);
                OPENSSL_free(bin_pkE);
                HPKE_err;
            }
            OPENSSL_free(bin_skE);
            OPENSSL_free(bin_pkE);

        } else
#endif
        if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
            HPKE_err;
        }
        EVP_PKEY_CTX_free(pctx); pctx = NULL;
    } else if (evpcaller) {

        pkE = extsenderpriv;

    } else if (rawcaller) {

        if (hpke_prbuf2evp(libctx, suite.kem_id,
                    rawsenderpriv, rawsenderprivlen, NULL, 0, &pkE) != 1) {
            HPKE_err;
        }
        if (!pkE) { HPKE_err; }

    }

    /* step 2 run DH KEM to get dh */
    enclen = EVP_PKEY_get1_encoded_public_key(pkE, &enc);
    if (enc == NULL || enclen == 0) {
        HPKE_err;
    }

    /* load auth key pair if using an auth mode */
    if (mode == HPKE_MODE_AUTH || mode == HPKE_MODE_PSKAUTH) {
#ifdef TESTVECTORS
        if (ltv) {
            unsigned char *bin_pkS = NULL; size_t bin_pkSlen = 0;
            if (1 != hpke_ah_decode(strlen(ltv->pkSm), ltv->pkSm,
                        &bin_pkSlen, &bin_pkS)) {
                HPKE_err;
            }
            erv = hpke_prbuf2evp(libctx, suite.kem_id, authpriv, authprivlen,
                    bin_pkS, bin_pkSlen, &skI);
        } else {
            erv = hpke_prbuf2evp(libctx, suite.kem_id, authpriv, authprivlen,
                    pub, publen, &skI);
        }
        if (erv != 1) goto err;
#else
        if (authpriv_evp != NULL) {
            skI = authpriv_evp;
        } else {
            erv = hpke_prbuf2evp(libctx, suite.kem_id, authpriv, authprivlen,
                pub, publen, &skI);
            if (erv != 1) goto err;
        }
#endif

        if (!skI) {
            erv = __LINE__;goto err;
        }
        mypublen = EVP_PKEY_get1_encoded_public_key(skI, &mypub);
        if (mypub == NULL || mypublen == 0) {
            HPKE_err;
        }
    }
    erv = hpke_do_kem(libctx, 1, suite, pkE, enclen, enc, pkR, publen, pub,
            skI, mypublen, mypub, &shared_secret, &shared_secretlen);
    if (erv != 1) goto err;
    if (mypub != NULL) { OPENSSL_free(mypub); mypub = NULL; }

    /* step 3. create context buffer */
    /* key_schedule_context */
    memset(ks_context, 0, HPKE_MAXSIZE);
    ks_context[0] = (unsigned char)(mode % 256); ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSKIDHASH_LABEL, strlen(HPKE_PSKIDHASH_LABEL),
                    (unsigned char*)pskid, pskidlen,
                    ks_context + 1, &halflen);
    if (erv != 1) goto err;
    ks_contextlen -= halflen;
    erv = hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_INFOHASH_LABEL, strlen(HPKE_INFOHASH_LABEL),
                    (unsigned char*)info, infolen,
                    ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) goto err;
    ks_contextlen += 1 + halflen;

    /* step 4. extracts and expands as needed */
#ifdef TESTVECTORS
    hpke_test_expand_extract();
#endif
    /* Extract secret and Expand variously...  */
    erv = hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSK_HASH_LABEL, strlen(HPKE_PSK_HASH_LABEL),
                    psk, psklen,
                    psk_hash, &psk_hashlen);
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tpsk_hash", psk_hash, psk_hashlen);
#endif
    kdf_ind=kdf_iana2index(suite.kdf_id);
    if (kdf_ind == 0 ) { HPKE_err; }
    if (erv != 1) goto err;
    secretlen = hpke_kdf_tab[kdf_ind].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        HPKE_err;
    }
    if (hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    shared_secret, shared_secretlen,
                    HPKE_SECRET_LABEL, strlen(HPKE_SECRET_LABEL),
                    psk, psklen,
                    secret, &secretlen) != 1) {
        HPKE_err;
    }
    aead_ind=aead_iana2index(suite.aead_id);
    if (aead_ind == 0 ) { HPKE_err; }
    noncelen = hpke_aead_tab[aead_ind].Nn;
    if (hpke_expand(libctx, suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_NONCE_LABEL, strlen(HPKE_NONCE_LABEL),
                    ks_context, ks_contextlen,
                    noncelen, nonce, &noncelen) != 1) {
        HPKE_err;
    }
    if (noncelen != hpke_aead_tab[aead_ind].Nn) {
        HPKE_err;
    }
    /* XOR sequence with nonce as needed */
    if (seq != NULL && seqlen > 0) {
        size_t sind;
        if (seqlen > noncelen) {
            HPKE_err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            unsigned char cv;
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }
    keylen = hpke_aead_tab[aead_ind].Nk;
    if (hpke_expand(libctx, suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_KEY_LABEL, strlen(HPKE_KEY_LABEL),
                    ks_context, ks_contextlen,
                    keylen, key, &keylen) != 1) {
        HPKE_err;
    }
    exporterlen = hpke_kdf_tab[kdf_ind].Nh;
    if (hpke_expand(libctx, suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_EXP_LABEL, strlen(HPKE_EXP_LABEL),
                    ks_context, ks_contextlen,
                    exporterlen, exporter, &exporterlen) != 1) {
        HPKE_err;
    }

    /* step 5. call the AEAD */
    arv = hpke_aead_enc(
                libctx, suite,
                key, keylen,
                nonce, noncelen,
                aad, aadlen,
                clear, clearlen,
                cipher, cipherlen);
    if (arv != 1) {
        erv = arv; goto err;
    }
    /* finish up */
    if (!evpcaller && !rawcaller) {
        if (enclen > *senderpublen) {
            HPKE_err;
        }
        memcpy(senderpub, enc, enclen);
        *senderpublen = enclen;
    }

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
                hpke_mode_strtab[mode], mode,
                hpke_kem_strtab[kem_ind], suite.kem_id,
                hpke_kdf_strtab[kdf_ind], suite.kdf_id,
                hpke_aead_strtab[aead_ind], suite.aead_id);

    if (pkE) {
        pblen = EVP_PKEY_get1_encoded_public_key(pkE, &pbuf);
        hpke_pbuf(stdout, "\tpkE", pbuf, pblen);
        if (pblen) OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkE is NULL\n");
    }
    if (pkR) {
        pblen = EVP_PKEY_get1_encoded_public_key(pkR, &pbuf);
        hpke_pbuf(stdout, "\tpkR", pbuf, pblen);
        if (pblen) OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkR is NULL\n");
    }
    if (skI) {
        pblen = EVP_PKEY_get1_encoded_public_key(skI, &pbuf);
        hpke_pbuf(stdout, "\tskI", pbuf, pblen);
        if (pblen) OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tskI is NULL\n");
    }
    hpke_pbuf(stdout, "\tshared_secret", shared_secret, shared_secretlen);
    hpke_pbuf(stdout, "\tks_context", ks_context, ks_contextlen);
    hpke_pbuf(stdout, "\tsecret", secret, secretlen);
    hpke_pbuf(stdout, "\tenc", enc, enclen);
    hpke_pbuf(stdout, "\tinfo", info, infolen);
    hpke_pbuf(stdout, "\taad", aad, aadlen);
    hpke_pbuf(stdout, "\tnonce", nonce, noncelen);
    hpke_pbuf(stdout, "\tkey", key, keylen);
    hpke_pbuf(stdout, "\texporter", exporter, exporterlen);
    hpke_pbuf(stdout, "\tplaintext", clear, clearlen);
    hpke_pbuf(stdout, "\tciphertext", cipher, *cipherlen);
    if (mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH) {
        fprintf(stdout, "\tpskid: %s\n", pskid);
        hpke_pbuf(stdout, "\tpsk", psk, psklen);
    }
#endif
    if (mypub != NULL) { OPENSSL_free(mypub); mypub = NULL; }
    if (bfp != NULL) BIO_free_all(bfp);
    if (pkR != NULL) EVP_PKEY_free(pkR);
    if (!evpcaller && pkE != NULL) EVP_PKEY_free(pkE);
    if (skI != NULL) EVP_PKEY_free(skI);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (shared_secret != NULL) OPENSSL_free(shared_secret);
    if (enc != NULL) OPENSSL_free(enc);
    return erv;
}

/*!
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite
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
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param clearlen length of the input buffer for cleartext
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_dec_int(
        OSSL_LIB_CTX  *libctx,
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t authpublen, unsigned char *authpub,
        size_t privlen, unsigned char *priv,
        EVP_PKEY *evppriv,
        size_t enclen, unsigned char *enc,
        size_t cipherlen, unsigned char *cipher,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t *clearlen, unsigned char *clear)
{
    int erv = 1;
    int crv = 1;
    int arv = 1;
    /* declare vars - done early so goto err works ok */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *pkI = NULL;
    size_t  shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t  ks_contextlen = HPKE_MAXSIZE;
    unsigned char ks_context[HPKE_MAXSIZE];
    size_t  secretlen = HPKE_MAXSIZE;
    unsigned char secret[HPKE_MAXSIZE];
    size_t  noncelen = HPKE_MAXSIZE;
    unsigned char nonce[HPKE_MAXSIZE];
    size_t  psk_hashlen = HPKE_MAXSIZE;
    unsigned char psk_hash[HPKE_MAXSIZE];
    size_t  keylen = HPKE_MAXSIZE;
    unsigned char key[HPKE_MAXSIZE];
    size_t  exporterlen = HPKE_MAXSIZE;
    unsigned char exporter[HPKE_MAXSIZE];
    size_t  mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;
    uint16_t aead_ind = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if ((crv = hpke_mode_check(mode)) != 1) return(crv);
    if ((crv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) return(crv);
    if ((crv = hpke_suite_check(suite)) != 1) return(crv);
    if (!(priv || evppriv) || !clearlen || !clear || !cipher) return(__LINE__);
    if ((mode == HPKE_MODE_AUTH || mode == HPKE_MODE_PSKAUTH) &&
            (!authpub || authpublen == 0)) return(__LINE__);
    if ((mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH) &&
            (!psk || psklen == 0 || !pskid)) return(__LINE__);
    kem_ind=kem_iana2index(suite.kem_id);
    if (kem_ind == 0 ) { HPKE_err; }

    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. load decryptors private key
     * 2. run DH KEM to get dh
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD
     *
     */
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("Decrypting:\n");
#endif

    /* step 0. Initialise peer's key(s) from string(s) */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkE = hpke_EVP_PKEY_new_raw_nist_public_key(libctx,
                hpke_kem_tab[kem_ind].groupid, 
                hpke_kem_tab[kem_ind].groupname, 
                enc, enclen);
    } else {
        pkE = EVP_PKEY_new_raw_public_key_ex(libctx,
                hpke_kem_tab[kem_ind].keytype, NULL , enc, enclen);
    }
    if (pkE == NULL) {
        HPKE_err;
    }
    if (authpublen != 0 && authpub != NULL) {
        if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
            pkI = hpke_EVP_PKEY_new_raw_nist_public_key(libctx,
                    hpke_kem_tab[kem_ind].groupid, 
                    hpke_kem_tab[kem_ind].groupname, 
                    authpub, authpublen);
        } else {
            pkI = EVP_PKEY_new_raw_public_key_ex(libctx,
                    hpke_kem_tab[kem_ind].keytype, NULL,
                    authpub, authpublen);
        }
        if (pkI == NULL) {
            HPKE_err;
        }
    }

    /* step 1. load decryptors private key */
    if (!evppriv) {
        erv = hpke_prbuf2evp(libctx, suite.kem_id, priv, privlen, NULL, 0, &skR);
        if (erv != 1) goto err;
        if (!skR) {
            erv = __LINE__;goto err;
        }
    } else {
        skR = evppriv;
    }

    /* step 2 run DH KEM to get dh */
    mypublen = EVP_PKEY_get1_encoded_public_key(skR, &mypub);
    if (mypub == NULL || mypublen == 0) {
        HPKE_err;
    }
    erv = hpke_do_kem(libctx, 0, suite, skR, mypublen, mypub, pkE, enclen, enc,
            pkI, authpublen, authpub, &shared_secret, &shared_secretlen);
    if (erv != 1) goto err;

    /* step 3. create context buffer */
    memset(ks_context, 0, HPKE_MAXSIZE);
    ks_context[0] = (unsigned char)(mode % 256); ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSKIDHASH_LABEL, strlen(HPKE_PSKIDHASH_LABEL),
                    (unsigned char*)pskid, pskidlen,
                    ks_context + 1, &halflen);
    if (erv != 1) goto err;
#ifdef SUPERVERBOSE
    hpke_pbuf(stdout, "\tpskidhash", ks_context + 1, halflen);
#endif
    ks_contextlen -= halflen;
    erv = hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_INFOHASH_LABEL, strlen(HPKE_INFOHASH_LABEL),
                    info, infolen,
                    ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) goto err;
#ifdef SUPERVERBOSE
    hpke_pbuf(stdout, "\tinfohash", ks_context + 1 + halflen, ks_contextlen);
#endif
    ks_contextlen += 1 + halflen;

    /* step 4. extracts and expands as needed */
    /* Extract secret and Expand variously...  */
    erv = hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSK_HASH_LABEL, strlen(HPKE_PSK_HASH_LABEL),
                    psk, psklen,
                    psk_hash, &psk_hashlen);
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tpsk_hash", psk_hash, psk_hashlen);
#endif
    if (erv != 1) goto err;
    kdf_ind=kdf_iana2index(suite.kdf_id);
    if (kdf_ind == 0 ) { HPKE_err; }
    secretlen = hpke_kdf_tab[kdf_ind].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        HPKE_err;
    }
    if (hpke_extract(libctx, suite, HPKE_5869_MODE_FULL,
                    shared_secret, shared_secretlen,
                    HPKE_SECRET_LABEL, strlen(HPKE_SECRET_LABEL),
                    psk, psklen,
                    secret, &secretlen) != 1) {
        HPKE_err;
    }
    aead_ind=aead_iana2index(suite.aead_id);
    if (aead_ind == 0 ) { HPKE_err; }
    noncelen = hpke_aead_tab[aead_ind].Nn;
    if (hpke_expand(libctx, suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_NONCE_LABEL, strlen(HPKE_NONCE_LABEL),
                    ks_context, ks_contextlen,
                    noncelen, nonce, &noncelen) != 1) {
        HPKE_err;
    }
    if (noncelen != hpke_aead_tab[aead_ind].Nn) {
        HPKE_err;
    }
    /* XOR sequence with nonce as needed */
    if (seq != NULL && seqlen > 0) {
        size_t sind;
        if (seqlen > noncelen) {
            HPKE_err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            unsigned char cv;
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }
    keylen = hpke_aead_tab[aead_ind].Nk;
    if (hpke_expand(libctx, suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_KEY_LABEL, strlen(HPKE_KEY_LABEL),
                    ks_context, ks_contextlen,
                    keylen, key, &keylen) != 1) {
        HPKE_err;
    }
    exporterlen = hpke_kdf_tab[kdf_ind].Nh;
    if (hpke_expand(libctx, suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_EXP_LABEL, strlen(HPKE_EXP_LABEL),
                    ks_context, ks_contextlen,
                    exporterlen, exporter, &exporterlen) != 1) {
        HPKE_err;
    }

    /* step 5. call the AEAD */
    arv = hpke_aead_dec(
                libctx, suite,
                key, keylen,
                nonce, noncelen,
                aad, aadlen,
                cipher, cipherlen,
                clear, clearlen);
    if (arv != 1) {
        erv = arv; goto err;
    }

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
                hpke_mode_strtab[mode], mode,
                hpke_kem_strtab[kem_ind], suite.kem_id,
                hpke_kdf_strtab[kdf_ind], suite.kdf_id,
                hpke_aead_strtab[aead_ind], suite.aead_id);
    if (pkE) {
        pblen = EVP_PKEY_get1_encoded_public_key(pkE, &pbuf);
        hpke_pbuf(stdout, "\tpkE", pbuf, pblen);
        if (pblen) OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkE is NULL\n");
    }
    if (skR) {
        pblen = EVP_PKEY_get1_encoded_public_key(skR, &pbuf);
        hpke_pbuf(stdout, "\tpkR", pbuf, pblen);
        if (pblen) OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkR is NULL\n");
    }
    if (pkI) {
        pblen = EVP_PKEY_get1_encoded_public_key(pkI, &pbuf);
        hpke_pbuf(stdout, "\tpkI", pbuf, pblen);
        if (pblen) OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tskI is NULL\n");
    }

    hpke_pbuf(stdout, "\tshared_secret", shared_secret, shared_secretlen);
    hpke_pbuf(stdout, "\tks_context", ks_context, ks_contextlen);
    hpke_pbuf(stdout, "\tsecret", secret, secretlen);
    hpke_pbuf(stdout, "\tenc", enc, enclen);
    hpke_pbuf(stdout, "\tinfo", info, infolen);
    hpke_pbuf(stdout, "\taad", aad, aadlen);
    hpke_pbuf(stdout, "\tnonce", nonce, noncelen);
    hpke_pbuf(stdout, "\tkey", key, keylen);
    hpke_pbuf(stdout, "\tciphertext", cipher, cipherlen);
    if (mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH) {
        fprintf(stdout, "\tpskid: %s\n", pskid);
        hpke_pbuf(stdout, "\tpsk", psk, psklen);
    }
    if (*clearlen != HPKE_MAXSIZE)
        hpke_pbuf(stdout, "\tplaintext", clear, *clearlen);
    else printf("clearlen is HPKE_MAXSIZE, so decryption probably failed\n");
#endif
    if (bfp != NULL) BIO_free_all(bfp);
    if (skR != NULL && evppriv == NULL) EVP_PKEY_free(skR);
    if (pkE != NULL) EVP_PKEY_free(pkE);
    if (pkI != NULL) EVP_PKEY_free(pkI);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (shared_secret != NULL) OPENSSL_free(shared_secret);
    if (mypub != NULL) OPENSSL_free(mypub);
    return erv;
}

/*!
 * @brief generate a key pair keeping private inside API
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key pointer
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg_evp(
        OSSL_LIB_CTX  *libctx,
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        EVP_PKEY **priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    unsigned char *lpub = NULL;
    size_t lpublen = 0;
    uint16_t kem_ind = 0;

    if (hpke_suite_check(suite) != 1) return(__LINE__);
    if (!pub || !priv) return(__LINE__);
    kem_ind=kem_iana2index(suite.kem_id);
    if (kem_ind == 0 ) { HPKE_err; }
    /* generate sender's key pair */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pctx = EVP_PKEY_CTX_new_from_name(libctx,
                hpke_kem_tab[kem_ind].keytype,
                hpke_kem_tab[kem_ind].groupname);
        if (pctx == NULL) {
            HPKE_err;
        }
        if (1 != EVP_PKEY_paramgen_init(pctx)) {
            HPKE_err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            HPKE_err;
        }
        if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                    hpke_kem_tab[kem_ind].groupid)) {
            HPKE_err;
        }
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(libctx,
                hpke_kem_tab[kem_ind].keytype, NULL);
        if (pctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            HPKE_err;
        }
    }
    if (EVP_PKEY_generate(pctx, &skR) <= 0) {
        HPKE_err;
    }
    EVP_PKEY_CTX_free(pctx); pctx = NULL;
    lpublen = EVP_PKEY_get1_encoded_public_key(skR, &lpub);
    if (lpub == NULL || lpublen == 0) {
        HPKE_err;
    }
    if (lpublen > *publen) {
        HPKE_err;
    }
    *publen = lpublen;
    memcpy(pub, lpub, lpublen);
    OPENSSL_free(lpub); lpub = NULL;
    *priv = skR;
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (lpub != NULL) OPENSSL_free(lpub);
    return(erv);

err:
    if (skR != NULL) EVP_PKEY_free(skR);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (lpub != NULL) OPENSSL_free(lpub);
    return(erv);
}

/*!
 * @brief generate a key pair
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg(
        OSSL_LIB_CTX  *libctx,
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        size_t *privlen, unsigned char *priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY *skR = NULL;
    BIO *bfp = NULL;
    unsigned char lpriv[HPKE_MAXSIZE];
    size_t lprivlen = 0;

    if (hpke_suite_check(suite) != 1) return(__LINE__);
    if (!pub || !priv) return(__LINE__);
    erv = hpke_kg_evp(libctx, mode, suite, publen, pub, &skR);
    if (erv != 1) {
        return(erv);
    }
    bfp = BIO_new(BIO_s_mem());
    if (!bfp) {
        HPKE_err;
    }
    if (!PEM_write_bio_PrivateKey(bfp, skR, NULL, NULL, 0, NULL, NULL)) {
        HPKE_err;
    }
    lprivlen = BIO_read(bfp, lpriv, HPKE_MAXSIZE);
    if (lprivlen <= 0) {
        HPKE_err;
    }
    if (lprivlen > *privlen) {
        HPKE_err;
    }
    *privlen = lprivlen;
    memcpy(priv, lpriv, lprivlen);

err:
    if (skR != NULL) EVP_PKEY_free(skR);
    if (bfp != NULL) BIO_free_all(bfp);
    return(erv);
}

/*!
 * @brief randomly pick a suite
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the result
 * @return 1 for success, otherwise failure
 *
 * If you change the structure of the various *_tab arrays
 * then this code will also need change.
 */
static int hpke_random_suite(OSSL_LIB_CTX *libctx, hpke_suite_t *suite)
{
    unsigned char rval = 0;
    int nkdfs = sizeof(hpke_kdf_tab) / sizeof(hpke_kdf_info_t) - 1;
    int naeads = sizeof(hpke_aead_tab) / sizeof(hpke_aead_info_t) - 1;
    int nkems = sizeof(hpke_kem_tab) / sizeof(hpke_kem_info_t) - 1;

    /* random kem */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), HPKE_RSTRENGTH) <= 0) 
        return(__LINE__);
    suite->kem_id = hpke_kem_tab[(rval % nkems + 1)].kem_id;

    /* random kdf */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), HPKE_RSTRENGTH) <= 0) 
        return(__LINE__);
    suite->kdf_id = hpke_kdf_tab[(rval % nkdfs + 1)].kdf_id;

    /* random aead */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), HPKE_RSTRENGTH) <= 0) 
        return(__LINE__);
    suite->aead_id = hpke_aead_tab[(rval % naeads + 1)].aead_id;
    return 1;
}

/*!
 * @brief return a (possibly) random suite, public key, ciphertext for GREASErs
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite-in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher buffer with random value of the appropriate length
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
static int hpke_good4grease(
        OSSL_LIB_CTX *libctx,
        hpke_suite_t *suite_in,
        hpke_suite_t *suite,
        unsigned char *pub,
        size_t *pub_len,
        unsigned char *cipher,
        size_t cipher_len)
{
    hpke_suite_t chosen;
    int crv = 0;
    int erv = 0;
    size_t plen = 0;
    uint16_t kem_ind = 0;
#ifdef SUPERVERBOSE
    uint16_t aead_ind = 0;
    uint16_t kdf_ind = 0;
#endif

    if (!pub || !pub_len || !cipher || !cipher_len || !suite) return(__LINE__);
    if (suite_in == NULL) {
        /* choose a random suite */
        crv = hpke_random_suite(libctx, &chosen);
        if (crv != 1) return(crv);
    } else {
        chosen = *suite_in;
    }
    kem_ind=kem_iana2index(chosen.kem_id);
    if (kem_ind == 0 ) { HPKE_err; }
#ifdef SUPERVERBOSE
    aead_ind=aead_iana2index(chosen.aead_id);
    if (aead_ind == 0 ) { HPKE_err; }
    kdf_ind=kdf_iana2index(chosen.kdf_id);
    if (kdf_ind == 0 ) { HPKE_err; }
    printf("GREASEy suite before check:\n\tkem: %s (%d)," \
           " kdf: %s (%d), aead: %s (%d)\n",
                hpke_kem_strtab[kem_ind], chosen.kem_id,
                hpke_kdf_strtab[kdf_ind], chosen.kdf_id,
                hpke_aead_strtab[aead_ind], chosen.aead_id);
#endif
    if ((crv = hpke_suite_check(chosen)) != 1) return(__LINE__);
    *suite=chosen;
    /* publen */
    plen = hpke_kem_tab[kem_ind].Npk;
    if (plen > *pub_len) return(__LINE__);
    if (RAND_bytes_ex(libctx, pub, plen, HPKE_RSTRENGTH) <= 0) 
        return(__LINE__);
    *pub_len = plen;
    if (RAND_bytes_ex(libctx, cipher, cipher_len, HPKE_RSTRENGTH) <= 0) 
        return(__LINE__);
#ifdef SUPERVERBOSE
    printf("GREASEy suite:\n\tkem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
                hpke_kem_strtab[kem_ind], chosen.kem_id,
                hpke_kdf_strtab[kdf_ind], chosen.kdf_id,
                hpke_aead_strtab[aead_ind], chosen.aead_id);
    hpke_pbuf(stdout, "GREASEy public", pub, *pub_len);
    hpke_pbuf(stdout, "GREASEy cipher", cipher, cipher_len);
#endif
    return 1;
err:
    return(erv);
}


/*
 * @brief string matching for suites
 */
#if defined(_WIN32)
#define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !_stricmp(inp, known))
#else
#define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !strcasecmp(inp, known))
#endif

/*!
 * @brief map a string to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
static int hpke_str2suite(char *suitestr, hpke_suite_t *suite)
{
    int erv = 0;
    uint16_t kem = 0, kdf = 0, aead = 0;
    char *st = NULL;
    char *instrcp = NULL;
    size_t inplen = 0;
    int labels = 0;

    if (!suitestr || !suite) return(__LINE__);
    /* See if it contains a mix of our strings and numbers  */

    inplen = OPENSSL_strnlen(suitestr,HPKE_MAX_SUITESTR);
    if (inplen >= HPKE_MAX_SUITESTR ) return(__LINE__);
    instrcp = OPENSSL_strndup(suitestr,inplen);
    st = strtok(instrcp, ",");
    if (!st) { 
        OPENSSL_free(instrcp);
        erv = __LINE__; return erv; 
    }
    while (st != NULL) {
        /* check if string is known or number and if so handle appropriately */
        if (kem == 0) {
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_P256)) kem = HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_P384)) kem = HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_P521)) kem = HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_X25519)) kem = HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_X448)) kem = HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st, "0x10")) kem = HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st, "16")) kem = HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st, "0x11")) kem = HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st, "17")) kem = HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st, "0x12")) kem = HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st, "18")) kem = HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st, "0x20")) kem = HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st, "32")) kem = HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st, "0x21")) kem = HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st, "33")) kem = HPKE_KEM_ID_448;
        } else if (kem != 0 && kdf == 0) {
            if (HPKE_MSMATCH(st, HPKE_KDFSTR_256)) kdf = 1;
            if (HPKE_MSMATCH(st, HPKE_KDFSTR_384)) kdf = 2;
            if (HPKE_MSMATCH(st, HPKE_KDFSTR_512)) kdf = 3;
            if (HPKE_MSMATCH(st, "0x01")) kdf = 1;
            if (HPKE_MSMATCH(st, "0x02")) kdf = 2;
            if (HPKE_MSMATCH(st, "0x03")) kdf = 3;
            if (HPKE_MSMATCH(st, "0x1")) kdf = 1;
            if (HPKE_MSMATCH(st, "0x2")) kdf = 2;
            if (HPKE_MSMATCH(st, "0x3")) kdf = 3;
            if (HPKE_MSMATCH(st, "1")) kdf = 1;
            if (HPKE_MSMATCH(st, "2")) kdf = 2;
            if (HPKE_MSMATCH(st, "3")) kdf = 3;
        } else if (kem != 0 && kdf != 0 && aead == 0) {
            if (HPKE_MSMATCH(st, HPKE_AEADSTR_AES128GCM)) aead = 1;
            if (HPKE_MSMATCH(st, HPKE_AEADSTR_AES256GCM)) aead = 2;
            if (HPKE_MSMATCH(st, HPKE_AEADSTR_CP)) aead = 3;
            if (HPKE_MSMATCH(st, "0x01")) aead = 1;
            if (HPKE_MSMATCH(st, "0x02")) aead = 2;
            if (HPKE_MSMATCH(st, "0x03")) aead = 3;
            if (HPKE_MSMATCH(st, "0x1")) aead = 1;
            if (HPKE_MSMATCH(st, "0x2")) aead = 2;
            if (HPKE_MSMATCH(st, "0x3")) aead = 3;
            if (HPKE_MSMATCH(st, "1")) aead = 1;
            if (HPKE_MSMATCH(st, "2")) aead = 2;
            if (HPKE_MSMATCH(st, "3")) aead = 3;
        }
        st = strtok(NULL, ",");
        labels++;
        if (labels > 3 ) {
            OPENSSL_free(instrcp);
            return(__LINE__);
        }
    }
    OPENSSL_free(instrcp);
    if (kem == 0 || kdf == 0 || aead == 0) { erv = __LINE__; return erv; }
    suite->kem_id = kem;
    suite->kdf_id = kdf;
    suite->aead_id = aead;
    return 1;
}

/*!
 * @brief tell the caller how big the cipertext will be
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who knows what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given suite.
 *
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
static int hpke_expansion(hpke_suite_t suite,
        size_t clearlen,
        size_t *cipherlen)
{
    int erv = 0;
    size_t tlen = 0;
    uint16_t aead_ind = 0;

    if (!cipherlen) {
        HPKE_err;
    }
    if ((erv = hpke_suite_check(suite)) != 1) {
        HPKE_err;
    }
    aead_ind=aead_iana2index(suite.aead_id);
    if (aead_ind == 0 ) { HPKE_err; }
    tlen = hpke_aead_tab[aead_ind].taglen;
    *cipherlen = tlen + clearlen;
    return 1;

err:
    return erv;
}

/*
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output.
 *
 *
 * @param libctx is the context to use (normally NULL)
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
int OSSL_HPKE_enc(
        OSSL_LIB_CTX *libctx,
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
        )
{
    return hpke_enc_int(libctx, mode, suite,
            pskid, psklen, psk,
            publen, pub,
            authprivlen, authpriv, authpriv_evp,
            clearlen, clear,
            aadlen, aad,
            infolen, info,
            seqlen, seq,
            0, NULL,
            NULL, 0, NULL,
            senderpublen, senderpub,
            cipherlen, cipher
#ifdef TESTVECTORS
            , tv
#endif
           );
}

/*
 * @brief HPKE encryption function, with externally supplied sender key pair
 *
 * This function is provided with an ECDH key pair that is used for
 * HPKE encryption.
 *
 * @param libctx is the context to use (normally NULL)
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
int OSSL_HPKE_enc_evp(
        OSSL_LIB_CTX *libctx,
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
        )
{
    return hpke_enc_int(libctx, mode, suite,
            pskid, psklen, psk,
            publen, pub,
            authprivlen, authpriv, authpriv_evp,
            clearlen, clear,
            aadlen, aad,
            infolen, info,
            seqlen, seq,
            senderpublen, senderpub, senderpriv, 
            0, NULL,
            0, NULL,
            cipherlen, cipher
#ifdef TESTVECTORS
            , tv
#endif
           );
}

/*
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use (normally NULL)
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
int OSSL_HPKE_dec(
        OSSL_LIB_CTX *libctx,
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
        size_t *clearlen, unsigned char *clear)
{
    return(hpke_dec_int(libctx, mode, suite,
                    pskid, psklen, psk,
                    publen, pub,
                    privlen, priv, evppriv,
                    enclen, enc,
                    cipherlen, cipher,
                    aadlen, aad,
                    infolen, info,
                    seqlen, seq,
                    clearlen, clear));
}

/*!
 * @brief generate a key pair
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_kg(
        OSSL_LIB_CTX *libctx,
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        size_t *privlen, unsigned char *priv)
{
    return(hpke_kg(libctx, mode, suite, publen, pub, privlen, priv));
}

/*!
 * @brief generate a key pair but keep private inside API
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_kg_evp(
        OSSL_LIB_CTX *libctx,
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        EVP_PKEY **priv)
{
    return(hpke_kg_evp(libctx, mode, suite, publen, pub, priv));
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not-1 otherwise
 */
int OSSL_HPKE_suite_check(
        hpke_suite_t suite)
{
    return(hpke_suite_check(suite));
}

/*!
 * @brief: map a kem_id and a private key buffer into an EVP_PKEY
 *
 * @param libctx is the context to use (normally NULL)
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
int OSSL_HPKE_prbuf2evp(
        OSSL_LIB_CTX *libctx,
        unsigned int kem_id,
        unsigned char *prbuf,
        size_t prbuf_len,
        unsigned char *pubuf,
        size_t pubuf_len,
        EVP_PKEY **priv)
{
    return(hpke_prbuf2evp(libctx, kem_id, prbuf, prbuf_len, pubuf,
                pubuf_len, priv));
}

/*!
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 *
 * As usual buffers are caller allocated and lengths on input are buffer size.
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite_in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_good4grease(
        OSSL_LIB_CTX *libctx,
        hpke_suite_t *suite_in,
        hpke_suite_t *suite,
        unsigned char *pub,
        size_t *pub_len,
        unsigned char *cipher,
        size_t cipher_len)
{
    return(hpke_good4grease(libctx,suite_in, suite, pub, pub_len, cipher, cipher_len));
}

/*!
 * @brief map a string to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_str2suite(
        char *str, 
        hpke_suite_t *suite)
{
    return(hpke_str2suite(str, suite));
}

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
int OSSL_HPKE_expansion(
        hpke_suite_t suite,
        size_t clearlen,
        size_t *cipherlen)
{
    return(hpke_expansion(suite, clearlen, cipherlen));
}
