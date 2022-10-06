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

#if !defined(OPENSSL_SYS_WINDOWS)
#include <arpa/inet.h>
#else
#include <winsock.h>
#endif

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <internal/packet.h>
#ifdef HAPPYKEY
#ifdef OSSL_KEM_PARAM_OPERATION_DHKEM
#warning "DHKEM approach"
#endif
/* if you don't have an openssl development tree you may need this */
# ifndef OSSL_NELEM
#  define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))
# endif
#else
#include <internal/common.h>
#endif
#ifdef HAPPYKEY
/*
 * If we're building standalone (from github.com/sftcd/happykey) then
 * include the local header.
 */
# include "hpke.h"
# include "hpke_util.h"
/*
 * Define this for LOADS of printing of intermediate cryptographic values
 * Really only needed when new crypto added (hopefully)
 */
# undef SUPERVERBOSE
# ifdef TESTVECTORS
#  include "hpketv.h"
# endif

#else /* For OpenSSL library */
#include <openssl/hpke.h>
#include <internal/hpke_util.h>
#include <openssl/err.h>
#endif

/** default buffer size for keys and internal buffers we use */
#ifndef OSSL_HPKE_MAXSIZE
# define OSSL_HPKE_MAXSIZE 512
#endif

/* Define HPKE labels from RFC 9180 in hex for EBCDIC compatibility */
#ifdef HAPPYKEY
/**< "HPKE-v1" -  version string label */
static const char OSSL_HPKE_VERLABEL[] = "\x48\x50\x4B\x45\x2D\x76\x31";
#endif
/**< "HPKE" - "suite_id" label for 5.1 */
static const char OSSL_HPKE_SEC51LABEL[] = "\x48\x50\x4b\x45";
#ifdef HAPPYKEY
/**< "eae_prk" - label in ExtractAndExpand */
static const char OSSL_HPKE_EAE_PRK_LABEL[] = "\x65\x61\x65\x5f\x70\x72\x6b";
#endif
/**< "psk_id_hash" - in key_schedule_context */
static const char OSSL_HPKE_PSKIDHASH_LABEL[] = "\x70\x73\x6b\x5f\x69\x64\x5f\x68\x61\x73\x68";
/**<  "info_hash" - in key_schedule_context */
static const char OSSL_HPKE_INFOHASH_LABEL[] = "\x69\x6e\x66\x6f\x5f\x68\x61\x73\x68";
#ifdef HAPPYKEY
/**<  "shared_secret" - shared secret calc label */
static const char OSSL_HPKE_SS_LABEL[] = "\x73\x68\x61\x72\x65\x64\x5f\x73\x65\x63\x72\x65\x74";
#endif
/**<  "base_nonce" - base nonce calc label */
static const char OSSL_HPKE_NONCE_LABEL[] = "\x62\x61\x73\x65\x5f\x6e\x6f\x6e\x63\x65";
/**<  "exp" - internal exporter secret generation label */
static const char OSSL_HPKE_EXP_LABEL[] = "\x65\x78\x70";
/**<  "sec" - external label for exporting secret */
static const char OSSL_HPKE_EXP_SEC_LABEL[] = "\x73\x65\x63";
/**<  "key" - label for use when generating key from shared secret */
static const char OSSL_HPKE_KEY_LABEL[] = "\x6b\x65\x79";
/**<  "psk_hash" - for hashing PSK */
static const char OSSL_HPKE_PSK_HASH_LABEL[] = "\x70\x73\x6b\x5f\x68\x61\x73\x68";
/**<  "secret" - for generating shared secret */
static const char OSSL_HPKE_SECRET_LABEL[] = "\x73\x65\x63\x72\x65\x74";
#ifdef HAPPYKEY
/**< "KEM" - "suite_id" label for 4.1 */
static const char OSSL_HPKE_SEC41LABEL[] = "\x4b\x45\x4d";
/**<  "dkp_prk" - DeriveKeyPair label */
static const char OSSL_HPKE_DPK_LABEL[] = "\x64\x6b\x70\x5f\x70\x72\x6b";
/**<  "candidate" - used in deterministic key gen */
static const char OSSL_HPKE_CAND_LABEL[] = "\x63\x61\x6e\x64\x69\x64\x61\x74\x65";
/**<  "sk" - label used in deterministic key gen */
static const char OSSL_HPKE_SK_LABEL[] = "\x73\x6b";
#endif

#ifdef HAPPYKEY
/* different RFC5869 "modes" used in RFC9180 */
#define OSSL_HPKE_5869_MODE_PURE   0 /**< Do "pure" RFC5869 */
#define OSSL_HPKE_5869_MODE_KEM    1 /**< Abide by HPKE section 4.1 */
#define OSSL_HPKE_5869_MODE_FULL   2 /**< Abide by HPKE section 5.1 */
/*
 * note that the "PURE" mode is not used in RFC9180 but having that
 * option allows us to verify our implementation using test vectors
 * for RFC5869 - that was useful in initial development and could be
 * again if we somehow break interop or the spec changes
 */
#endif
/*
 * PEM header/footer for private keys
 * PEM_STRING_PKCS8INF is just: "PRIVATE KEY"
 */
#define PEM_PRIVATEHEADER "-----BEGIN "PEM_STRING_PKCS8INF"-----\n"
#define PEM_PRIVATEFOOTER "\n-----END "PEM_STRING_PKCS8INF"-----\n"

/* max string len we'll try map to a suite */
#define OSSL_HPKE_MAX_SUITESTR 38

/* "strength" input to RAND_bytes_ex */
#define OSSL_HPKE_RSTRENGTH 10

/* an error macro just to make things easier */
#ifdef HAPPYKEY
# define ERR_raise(__a__, __b__) \
    { \
        if (erv == 1) { erv = 0; } \
    }
#endif
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
unsigned char *pbuf; /**< global var for debug printing */
size_t pblen = 1024; /**< global var for debug printing */

/*
 * @brief table of mode strings
 */
static const char *hpke_mode_strtab[] = {
    OSSL_HPKE_MODESTR_BASE,
    OSSL_HPKE_MODESTR_PSK,
    OSSL_HPKE_MODESTR_AUTH,
    OSSL_HPKE_MODESTR_PSKAUTH};
#endif

#ifdef HAPPYKEY
/*
 * @brief  Map ascii to binary - utility macro used in >1 place
 */
# define HPKE_A2B(_c_) (_c_ >= '0' && _c_ <= '9' ? (_c_ - '0') :\
                        (_c_ >= 'A' && _c_ <= 'F' ? (_c_ - 'A' + 10) :\
                         (_c_ >= 'a' && _c_ <= 'f' ? (_c_ - 'a' + 10) : 0)))
#endif
/*
 * @brief info about an AEAD
 */
typedef struct {
    uint16_t            aead_id; /**< code point for aead alg */
    const char *        name;   /* alg name */
    size_t              taglen; /**< aead tag len */
    size_t              Nk; /**< size of a key for this aead */
    size_t              Nn; /**< length of a nonce for this aead */
} hpke_aead_info_t;

/*
 * @brief table of AEADs
 */
static hpke_aead_info_t hpke_aead_tab[] = {
    { 0, NULL, 0, 0, 0 }, /* treat 0 as error so nothing here */
    { OSSL_HPKE_AEAD_ID_AES_GCM_128, LN_aes_128_gcm, 16, 16, 12 },
    { OSSL_HPKE_AEAD_ID_AES_GCM_256, LN_aes_256_gcm, 16, 32, 12 },
#ifndef OPENSSL_NO_CHACHA20
# ifndef OPENSSL_NO_POLY1305
    { OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, LN_chacha20_poly1305, 16, 32, 12 },
# endif
    { OSSL_HPKE_AEAD_ID_EXPORTONLY, LN_aes_128_gcm, 16, 16, 12 }
#endif
};
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*
 * @brief table of AEAD strings
 */
static const char *hpke_aead_strtab[] = {
    NULL,
    OSSL_HPKE_AEADSTR_AES128GCM,
    OSSL_HPKE_AEADSTR_AES256GCM,
# ifndef OPENSSL_NO_CHACHA20
#  ifndef OPENSSL_NO_POLY1305
    OSSL_HPKE_AEADSTR_CP,
#  endif
# endif
    OSSL_HPKE_AEADSTR_EXP
};
#endif

/*
 * @brief info about a KEM
 */
typedef struct {
    uint16_t       kem_id; /**< code point for key encipherment method */
    const char     *keytype; /**< string form of algtype "EC"/"X25519"/"X448" */
    const char     *groupname; /**< string form of EC group for NIST curves  */
    int            groupid; /**< NID of KEM */
    const char     *mdname; /**< hash alg name for the HKDF */
    size_t         Nsecret; /**< size of secrets */
    size_t         Nenc; /**< length of encapsulated key */
    size_t         Npk; /**< length of public key */
    size_t         Npriv; /**< length of raw private key */
} hpke_kem_info_t;

/*
 * @brief table of KEMs
 */
static hpke_kem_info_t hpke_kem_tab[] = {
    { 0, NULL, NULL, 0, NULL, 0, 0, 0 }, /* treat 0 as error so nowt here */
    { OSSL_HPKE_KEM_ID_P256, "EC", OSSL_HPKE_KEMSTR_P256, NID_X9_62_prime256v1,
      LN_sha256, 32, 65, 65, 32 },
    { OSSL_HPKE_KEM_ID_P384, "EC", OSSL_HPKE_KEMSTR_P384, NID_secp384r1,
      LN_sha384, 48, 97, 97, 48 },
    { OSSL_HPKE_KEM_ID_P521, "EC", OSSL_HPKE_KEMSTR_P521, NID_secp521r1,
      LN_sha512, 64, 133, 133, 66 },
    { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KEMSTR_X25519, NULL, NID_X25519,
      LN_sha256, 32, 32, 32, 32 },
    { OSSL_HPKE_KEM_ID_X448, OSSL_HPKE_KEMSTR_X448, NULL, NID_X448,
      LN_sha512, 64, 56, 56, 56 }
};
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*
 * @brief table of KEM strings
 *
 * Note: This also need blanks
 */
const char *hpke_kem_strtab[] = {
    NULL,
    OSSL_HPKE_KEMSTR_P256,
    OSSL_HPKE_KEMSTR_P384,
    OSSL_HPKE_KEMSTR_P521,
    OSSL_HPKE_KEMSTR_X25519,
    OSSL_HPKE_KEMSTR_X448 };
#endif

/*
 * @brief info about a KDF
 */
typedef struct {
    uint16_t       kdf_id; /**< code point for KDF */
    const char     *mdname; /**< hash alg name for the HKDF */
    size_t         Nh; /**< length of hash/extract output */
} hpke_kdf_info_t;

/*
 * @brief table of KDFs
 */
static hpke_kdf_info_t hpke_kdf_tab[] = {
    { 0, NULL, 0 }, /* keep indexing correct */
    { OSSL_HPKE_KDF_ID_HKDF_SHA256, LN_sha256, 32 },
    { OSSL_HPKE_KDF_ID_HKDF_SHA384, LN_sha384, 48 },
    { OSSL_HPKE_KDF_ID_HKDF_SHA512, LN_sha512, 64 }
};
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*
 * @brief table of KDF strings
 */
const char *hpke_kdf_strtab[] = {
    NULL,
    OSSL_HPKE_KDFSTR_256,
    OSSL_HPKE_KDFSTR_384,
    OSSL_HPKE_KDFSTR_512};
#endif

/**
 * @brief sender or receiver context
 */
struct ossl_hpke_ctx_st
{
    OSSL_LIB_CTX *libctx; /**< library context */
    char *propq; /**< properties */
    int mode; /**< HPKE mode */
    OSSL_HPKE_SUITE suite; /**< suite */
    uint64_t seq; /**< sequence number */
    unsigned char *shared_secret;
    size_t shared_secretlen;
    unsigned char *exportersec; /**< exporter secret */
    size_t exporterseclen;
    char *pskid; /**< PSK stuff */
    unsigned char *psk;
    size_t psklen;
    EVP_PKEY *senderpriv; /**< sender's ephemeral private key */
    char *ikme;
    size_t ikmelen;
    EVP_PKEY *authpriv; /**< sender's authentication private key */
    unsigned char *authpub; /**< auth public key */
    size_t authpublen;
};

/*
 * @brief map from IANA codepoint to AEAD table index
 *
 * @param codepoint should be an IANA code point
 * @return index in AEAD table or 0 if error
 */
static uint16_t aead_iana2index(uint16_t codepoint)
{
    uint16_t naeads = OSSL_NELEM(hpke_aead_tab);
    uint16_t i = 0;

    for (i = 0; i != naeads; i++) {
        if (hpke_aead_tab[i].aead_id == codepoint) {
            return i;
        }
    }
    return 0;
}

/*
 * @brief map from IANA codepoint to KEM table index
 *
 * @param codepoint should be an IANA code point
 * @return index in KEM table or 0 if error
 */
static uint16_t kem_iana2index(uint16_t codepoint)
{
    uint16_t nkems = OSSL_NELEM(hpke_kem_tab);
    uint16_t i = 0;

    for (i = 0; i != nkems; i++) {
        if (hpke_kem_tab[i].kem_id == codepoint) {
            return i;
        }
    }
    return 0;
}

/*
 * @brief map from IANA codepoint to AEAD table index
 *
 * @param codepoint should be an IANA code point
 * @return index in AEAD table or 0 if error
 */
static uint16_t kdf_iana2index(uint16_t codepoint)
{
    uint16_t nkdfs = OSSL_NELEM(hpke_kdf_tab);
    uint16_t i = 0;

    for (i = 0; i != nkdfs; i++) {
        if (hpke_kdf_tab[i].kdf_id == codepoint) {
            return i;
        }
    }
    return 0;
}
#ifdef HAPPYKEY
/*
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

/*
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good otherwise bad
 */
static int hpke_ah_decode(size_t ahlen, const char *ah,
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
    for (i = ahlen - 1; i > nibble; i -= 2) {
        int j = i / 2;

        lbuf[j] = HPKE_A2B(ah[i - 1]) * 16 + HPKE_A2B(ah[i]);
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
/*
 * @brief for odd/occasional debugging
 *
 * @param fout is a FILE * to use
 * @param msg is prepended to print
 * @param buf is the buffer to print
 * @param blen is the length of the buffer
 * @return 1 for success
 */
static int hpke_pbuf(FILE *fout, const char *msg,
                     const unsigned char *buf, size_t blen)
{
    size_t i = 0;

    if (fout == NULL) {
        return 0;
    }
    if (msg == NULL) {
        fprintf(fout, "NULL msg:");
    } else {
        fprintf(fout, "%s (%lu): ", msg, blen);
    }
    if (buf == NULL) {
        fprintf(fout, "buf is NULL, so probably something wrong\n");
        return 1;
    }
    if (blen == OSSL_HPKE_MAXSIZE) {
        fprintf(fout, "length is OSSL_HPKE_MAXSIZE, so probably unused\n");
        return 1;
    }
    if (blen == 0) {
        fprintf(fout, "length is 0, so probably something wrong\n");
        return 1;
    }
    for (i = 0; i < blen; i++) { fprintf(fout, "%02x", buf[i]); }
    fprintf(fout, "\n");
    return 1;
}
#endif

/*
 * @brief Check if kem_id is ok/known to us
 * @param kem_id is the externally supplied kem_id
 * @return 1 for good, not 1 for error
 */
static int hpke_kem_id_check(uint16_t kem_id)
{
    switch (kem_id) {
    case OSSL_HPKE_KEM_ID_P256:
    case OSSL_HPKE_KEM_ID_P384:
    case OSSL_HPKE_KEM_ID_P521:
    case OSSL_HPKE_KEM_ID_X25519:
    case OSSL_HPKE_KEM_ID_X448:
        break;
    default:
        return 0;
    }
    return 1;
}

/*
 * @brief check if KEM uses NIST curve or not
 * @param kem_id is the externally supplied kem_id
 * @return 1 for NIST, 0 for good-but-non-NIST, other otherwise
 */
static int hpke_kem_id_nist_curve(uint16_t kem_id)
{
    switch (kem_id) {
    case OSSL_HPKE_KEM_ID_P256:
    case OSSL_HPKE_KEM_ID_P384:
    case OSSL_HPKE_KEM_ID_P521:
        return 1;
    default:
        return 0;
    }
    return 0;
}

/*
 * @brief hpke wrapper to import NIST curve public key as easily as x25519/x448
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param curve is the curve NID
 * @param gname is the curve groupname
 * @param buf is the binary buffer with the (uncompressed) public value
 * @param buflen is the length of the private key buffer
 * @return a working EVP_PKEY * or NULL
 */
static EVP_PKEY * EVP_PKEY_new_raw_nist_public_key(OSSL_LIB_CTX *libctx,
                                                   const char *propq,
                                                   int curve,
                                                   const char *gname,
                                                   const unsigned char *buf,
                                                   size_t buflen)
{
#ifdef HAPPYKEY
    /*
     * s3_lib.c:ssl_generate_param_group has similar code so
     * can be useful if the upstream code changes
     */
#endif
    int erv = 1;
    EVP_PKEY *ret = NULL;
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);

    if (cctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_paramgen_init(cctx) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(cctx, curve) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_paramgen(cctx, &ret) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_set1_encoded_public_key(ret, buf, buflen) != 1) {
        EVP_PKEY_free(ret);
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
        /* needed for printing below */
        ret = NULL;
#endif
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    if (ret != NULL) {
        pblen = EVP_PKEY_get1_encoded_public_key(ret, &pbuf);
        hpke_pbuf(stdout, "\tEARLY public", pbuf, pblen);
        OPENSSL_free(pbuf);
    } else {
        printf("no EARLY public\n");
    }
#endif
    EVP_PKEY_CTX_free(cctx);
    if (erv == 1)
        return ret;
    else
        return NULL;
}

/*
 * @brief do the AEAD decryption
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
static int hpke_aead_dec(OSSL_LIB_CTX *libctx, const char *propq,
                         OSSL_HPKE_SUITE suite,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *cipher, size_t cipherlen,
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

    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    taglen = hpke_aead_tab[aead_ind].taglen;
    plaintext = OPENSSL_malloc(cipherlen);
    if (plaintext == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise the encryption operation */
    enc = EVP_CIPHER_fetch(libctx, hpke_aead_tab[aead_ind].name, propq);
    if (enc == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide AAD. */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &len, cipher,
                          cipherlen - taglen) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    plaintextlen = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                             taglen, (void *)(cipher + cipherlen - taglen))) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Finalise decryption.  */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (plaintextlen > *plainlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *plainlen = plaintextlen;
    memcpy(plain, plaintext, plaintextlen);

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    OPENSSL_free(plaintext);
    return erv;
}

/*
 * @brief do AEAD encryption as per the RFC
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
static int hpke_aead_enc(OSSL_LIB_CTX *libctx, const char *propq,
                         OSSL_HPKE_SUITE suite,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *plain, size_t plainlen,
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

    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    taglen = hpke_aead_tab[aead_ind].taglen;
    if (taglen != 16) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((taglen + plainlen) > *cipherlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Allocate this much extra for ciphertext and check the AEAD
     * doesn't require more - If it does, we'll fail.
     */
    ciphertext = OPENSSL_malloc(plainlen + taglen);
    if (ciphertext == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise the encryption operation. */
    enc = EVP_CIPHER_fetch(libctx, hpke_aead_tab[aead_ind].name, propq);
    if (enc == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide any AAD data. */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plainlen) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ciphertextlen = len;
    /* Finalise the encryption. */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ciphertextlen += len;
    /*
     * Get the tag This isn't a duplicate so needs to be added to the ciphertext
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(ciphertext + ciphertextlen, tag, taglen);
    ciphertextlen += taglen;
    if (ciphertextlen > *cipherlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *cipherlen = ciphertextlen;
    memcpy(cipher, ciphertext, ciphertextlen);

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    OPENSSL_free(ciphertext);
    return erv;
}
#ifdef HAPPYKEY
/*
 * @brief RFC5869 HKDF-Extract
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
 * - OSSL_HPKE_5869_MODE_PURE meaning to ignore all the
 *   HPKE-specific labelling and produce an output that's
 *   RFC5869 compliant (useful for testing and maybe
 *   more)
 * - OSSL_HPKE_5869_MODE_KEM meaning to follow section 4.1
 *   where the suite_id is used as:
 *   concat("KEM", I2OSP(kem_id, 2))
 * - OSSL_HPKE_5869_MODE_FULL meaning to follow section 5.1
 *   where the suite_id is used as:
 *     concat("HPKE", I2OSP(kem_id, 2),
 *          I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
 *
 * Isn't that a bit of a mess!
 */
static int hpke_extract(OSSL_LIB_CTX *libctx, const char *propq,
                        const OSSL_HPKE_SUITE suite, const int mode5869,
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
    unsigned char labeled_ikmbuf[2 * OSSL_HPKE_MAXSIZE];
    unsigned char *labeled_ikm = labeled_ikmbuf;
    size_t labeled_ikmlen = 0;
    int erv = 1;
    size_t lsecretlen = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;
    WPACKET pkt;

    if (!WPACKET_init_static_len(&pkt, labeled_ikmbuf,
                                 sizeof(labeled_ikmbuf), 0))
        goto err;
    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {

    case OSSL_HPKE_5869_MODE_PURE:
        labeled_ikmlen = ikmlen;
        labeled_ikm = (unsigned char *)ikm;
        break;

    case OSSL_HPKE_5869_MODE_KEM:
        if (!WPACKET_memcpy(&pkt, OSSL_HPKE_VERLABEL,
                            strlen(OSSL_HPKE_VERLABEL))
            || !WPACKET_memcpy(&pkt, OSSL_HPKE_SEC41LABEL,
                               strlen(OSSL_HPKE_SEC41LABEL))
            || !WPACKET_put_bytes_u16(&pkt, suite.kem_id)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_memcpy(&pkt, ikm, ikmlen)
            || !WPACKET_get_total_written(&pkt, &labeled_ikmlen)
            || !WPACKET_finish(&pkt))
            goto err;
        break;

    case OSSL_HPKE_5869_MODE_FULL:
        if (!WPACKET_memcpy(&pkt, OSSL_HPKE_VERLABEL,
                            strlen(OSSL_HPKE_VERLABEL))
            || !WPACKET_memcpy(&pkt, OSSL_HPKE_SEC51LABEL,
                               strlen(OSSL_HPKE_SEC51LABEL))
            || !WPACKET_put_bytes_u16(&pkt, suite.kem_id)
            || !WPACKET_put_bytes_u16(&pkt, suite.kdf_id)
            || !WPACKET_put_bytes_u16(&pkt, suite.aead_id)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_memcpy(&pkt, ikm, ikmlen)
            || !WPACKET_get_total_written(&pkt, &labeled_ikmlen)
            || !WPACKET_finish(&pkt))
            goto err;
        break;

    default:
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(libctx, "hkdf", propq)) == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == OSSL_HPKE_5869_MODE_KEM) {
        kem_ind = kem_iana2index(suite.kem_id);
        if (kem_ind == 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = hpke_kem_tab[kem_ind].mdname;
    } else {
        kdf_ind = kdf_iana2index(suite.kdf_id);
        if (kdf_ind == 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = hpke_kdf_tab[kdf_ind].mdname;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *)labeled_ikm,
                                             labeled_ikmlen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             (unsigned char *)salt, saltlen);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    lsecretlen = EVP_KDF_CTX_get_kdf_size(kctx);
    if (lsecretlen > *secretlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, secret, lsecretlen, params) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *secretlen = lsecretlen;

err:
    WPACKET_cleanup(&pkt);
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    memset(labeled_ikmbuf, 0, sizeof(labeled_ikmbuf));
    return erv;
}

/*
 * @brief RFC5869 HKDF-Expand
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
static int hpke_expand(OSSL_LIB_CTX *libctx, const char *propq,
                       const OSSL_HPKE_SUITE suite, const int mode5869,
                       const unsigned char *prk, const size_t prklen,
                       const char *label, const size_t labellen,
                       const unsigned char *info, const size_t infolen,
                       const uint32_t L,
                       unsigned char *out, size_t *outlen)
{
    int erv = 1;
    unsigned char libuf[2 * OSSL_HPKE_MAXSIZE];
    size_t concat_offset = 0;
    size_t loutlen = L;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
    const char *mdname = NULL;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;
    WPACKET pkt;

    if (!WPACKET_init_static_len(&pkt, libuf, sizeof(libuf), 0))
        goto err;
    if (L > *outlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {
    case OSSL_HPKE_5869_MODE_PURE:
        if (!WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_memcpy(&pkt, info, infolen)
            || !WPACKET_get_total_written(&pkt, &concat_offset)
            || !WPACKET_finish(&pkt))
            goto err;
        break;

    case OSSL_HPKE_5869_MODE_KEM:
        if (!WPACKET_put_bytes_u16(&pkt, L)
            || !WPACKET_memcpy(&pkt, OSSL_HPKE_VERLABEL,
                               strlen(OSSL_HPKE_VERLABEL))
            || !WPACKET_memcpy(&pkt, OSSL_HPKE_SEC41LABEL,
                               strlen(OSSL_HPKE_SEC41LABEL))
            || !WPACKET_put_bytes_u16(&pkt, suite.kem_id)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || (info == NULL ? 0 : !WPACKET_memcpy(&pkt, info, infolen))
            || !WPACKET_get_total_written(&pkt, &concat_offset)
            || !WPACKET_finish(&pkt))
            goto err;
        break;

    case OSSL_HPKE_5869_MODE_FULL:
        if (!WPACKET_put_bytes_u16(&pkt, L)
            || !WPACKET_memcpy(&pkt, OSSL_HPKE_VERLABEL,
                               strlen(OSSL_HPKE_VERLABEL))
            || !WPACKET_memcpy(&pkt, OSSL_HPKE_SEC51LABEL,
                               strlen(OSSL_HPKE_SEC51LABEL))
            || !WPACKET_put_bytes_u16(&pkt, suite.kem_id)
            || !WPACKET_put_bytes_u16(&pkt, suite.kdf_id)
            || !WPACKET_put_bytes_u16(&pkt, suite.aead_id)
            || !WPACKET_memcpy(&pkt, label, labellen)
            || !WPACKET_memcpy(&pkt, info, infolen)
            || !WPACKET_get_total_written(&pkt, &concat_offset)
            || !WPACKET_finish(&pkt))
            goto err;
        break;

    default:
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(libctx, "hkdf", propq)) == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == OSSL_HPKE_5869_MODE_KEM) {
        kem_ind = kem_iana2index(suite.kem_id);
        if (kem_ind == 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = hpke_kem_tab[kem_ind].mdname;
    } else {
        kdf_ind = kdf_iana2index(suite.kdf_id);
        if (kdf_ind == 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = hpke_kdf_tab[kdf_ind].mdname;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *) prk, prklen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                             libuf, concat_offset);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, out, loutlen, params) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *outlen = loutlen;

err:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    memset(libuf, 0, sizeof(libuf));
    return erv;
}

/*
 * @brief ExtractAndExpand
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
static int hpke_extract_and_expand(OSSL_LIB_CTX *libctx, const char *propq,
                                   OSSL_HPKE_SUITE suite, int mode5869,
                                   unsigned char *shared_secret,
                                   size_t shared_secretlen,
                                   unsigned char *context, size_t contextlen,
                                   unsigned char *secret, size_t *secretlen)
{
    int erv = 1;
    unsigned char eae_prkbuf[OSSL_HPKE_MAXSIZE];
    size_t eae_prklen = OSSL_HPKE_MAXSIZE;
    size_t lsecretlen = 0;
    uint16_t kem_ind = 0;

    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    lsecretlen = hpke_kem_tab[kem_ind].Nsecret;
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\teae_ssinput", shared_secret, shared_secretlen);
    hpke_pbuf(stdout, "\teae_context", context, contextlen);
    printf("\tNsecret: %lu\n", lsecretlen);
#endif
    erv = hpke_extract(libctx, propq, suite, mode5869,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_EAE_PRK_LABEL, strlen(OSSL_HPKE_EAE_PRK_LABEL),
                       shared_secret, shared_secretlen,
                       eae_prkbuf, &eae_prklen);
    if (erv != 1) { goto err; }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\teae_prk", eae_prkbuf, eae_prklen);
#endif
    erv = hpke_expand(libctx, propq, suite, mode5869,
                      eae_prkbuf, eae_prklen,
                      OSSL_HPKE_SS_LABEL, strlen(OSSL_HPKE_SS_LABEL),
                      context, contextlen,
                      lsecretlen, secret, &lsecretlen);
    if (erv != 1) { goto err; }
    *secretlen = lsecretlen;
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tshared secret", secret, *secretlen);
#endif
err:
    memset(eae_prkbuf, 0, sizeof(eae_prkbuf));
    return erv;
}

#ifdef TESTVECTORS
/*
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
    size_t OKMlen = OSSL_HPKE_MAXSIZE;
    unsigned char calc_prk[OSSL_HPKE_MAXSIZE];
    size_t PRKlen = OSSL_HPKE_MAXSIZE;
    unsigned char calc_okm[OSSL_HPKE_MAXSIZE];
    int rv = 1;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;

    rv = hpke_extract(NULL, NULL, suite, OSSL_HPKE_5869_MODE_PURE,
                      salt, saltlen, "", 0, IKM, IKMlen, calc_prk, &PRKlen);
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
    rv = hpke_expand(NULL, NULL, suite, OSSL_HPKE_5869_MODE_PURE, PRK, PRKlen,
                     (unsigned char *)"", 0, info, infolen, OKMlen,
                     calc_okm, &OKMlen);
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
    return rv;
}
#endif
/*
 * @brief run the KEM with two keys as required
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
static int hpke_do_kem(OSSL_LIB_CTX *libctx, const char *propq,
                       int encrypting, OSSL_HPKE_SUITE suite,
                       EVP_PKEY *key1,
                       size_t key1enclen, const unsigned char *key1enc,
                       EVP_PKEY *key2,
                       size_t key2enclen, const unsigned char *key2enc,
                       EVP_PKEY *akey,
                       size_t apublen, const unsigned char *apub,
                       unsigned char **ss, size_t *sslen)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    size_t zzlen = 2 * OSSL_HPKE_MAXSIZE;
    unsigned char zz[2 * OSSL_HPKE_MAXSIZE];
    size_t kem_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char kem_context[OSSL_HPKE_MAXSIZE];
    size_t lsslen = OSSL_HPKE_MAXSIZE;
    unsigned char lss[OSSL_HPKE_MAXSIZE];

    /* step 2 run DH KEM to get zz */
    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, propq);
    if (pctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &zzlen) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (zzlen >= OSSL_HPKE_MAXSIZE) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, zz, &zzlen) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    kem_contextlen = key1enclen + key2enclen;
    if (kem_contextlen >= OSSL_HPKE_MAXSIZE) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (encrypting) {
        memcpy(kem_context, key1enc, key1enclen);
        memcpy(kem_context + key1enclen, key2enc, key2enclen);
    } else {
        memcpy(kem_context, key2enc, key2enclen);
        memcpy(kem_context + key2enclen, key1enc, key1enclen);
    }
    if (apublen > 0) {
        /* Append the public auth key (mypub) to kem_context */
        if ((kem_contextlen + apublen) >= OSSL_HPKE_MAXSIZE) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(kem_context + kem_contextlen, apub, apublen);
        kem_contextlen += apublen;
    }

    if (akey != NULL) {
        size_t zzlen2 = 0;

        /* step 2 run to get 2nd half of zz */
        if (encrypting) {
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, akey, propq);
        } else {
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, propq);
        }
        if (pctx == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (encrypting) {
            if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0) {
                erv = 0;
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            if (EVP_PKEY_derive_set_peer(pctx, akey) <= 0) {
                erv = 0;
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        if (EVP_PKEY_derive(pctx, NULL, &zzlen2) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (zzlen2 >= OSSL_HPKE_MAXSIZE) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_derive(pctx, zz + zzlen, &zzlen2) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        zzlen += zzlen2;
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
    }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tkem_context", kem_context, kem_contextlen);
    hpke_pbuf(stdout, "\tzz", zz, zzlen);
#endif
    erv = hpke_extract_and_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_KEM,
                                  zz, zzlen, kem_context, kem_contextlen,
                                  lss, &lsslen);
    if (erv != 1) { goto err; }
    *ss = OPENSSL_malloc(lsslen);
    if (*ss == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(*ss, lss, lsslen);
    *sslen = lsslen;

err:
    EVP_PKEY_CTX_free(pctx);
    return erv;
}

/*
 * @brief check mode is in-range and supported
 * @param mode is the caller's chosen mode
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_mode_check(unsigned int mode)
{
    switch (mode) {
    case OSSL_HPKE_MODE_BASE:
    case OSSL_HPKE_MODE_PSK:
    case OSSL_HPKE_MODE_AUTH:
    case OSSL_HPKE_MODE_PSKAUTH:
        break;
    default:
        return 0;
    }
    return 1;
}

/*
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
static int hpke_psk_check(unsigned int mode,
                          const char *pskid,
                          size_t psklen,
                          const unsigned char *psk)
{
    if (mode == OSSL_HPKE_MODE_BASE || mode == OSSL_HPKE_MODE_AUTH)
        return 1;
    if (pskid == NULL || psklen == 0 || psk == NULL)
        return 0;
    return 1;
}
#endif
/*
 * @brief map a kem_id and a private key buffer into an EVP_PKEY
 *
 * Note that the buffer is expected to be some form of the encoded
 * private key, and could still have the PEM header or not, and might
 * or might not be base64 encoded. We'll try handle all those options.
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, otherwise failure
 */
static int hpke_prbuf2evp(OSSL_LIB_CTX *libctx, const char *propq,
                          unsigned int kem_id,
                          const unsigned char *prbuf, size_t prbuf_len,
                          const unsigned char *pubuf, size_t pubuf_len,
                          EVP_PKEY **retpriv)
{
    int erv = 0;
    EVP_PKEY *lpriv = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *priv = NULL;
    const char *keytype = NULL;
    const char *groupname = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    uint16_t kem_ind = 0;
#ifndef OPENSSL_NO_EC
    int groupnid = 0;
    size_t pubsize = 0;
    BIGNUM *calc_priv = NULL;
    EC_POINT *calc_pub = NULL;
    EC_GROUP *curve = NULL;
    unsigned char calc_pubuf[OSSL_HPKE_MAXSIZE];
    size_t calc_pubuf_len = OSSL_HPKE_MAXSIZE;
    point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
#endif
    unsigned char hf_prbuf[OSSL_HPKE_MAXSIZE];
    size_t hf_prbuf_len = 0;

    if (hpke_kem_id_check(kem_id) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    kem_ind = kem_iana2index(kem_id);
    if (kem_ind == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    keytype = hpke_kem_tab[kem_ind].keytype;
    groupname = hpke_kem_tab[kem_ind].groupname;
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("\tCalled hpke_prbuf2evp with kem id: %04x\n", kem_id);
    hpke_pbuf(stdout, "\thpke_prbuf2evp priv input", prbuf, prbuf_len);
    if (pubuf != NULL) {
        hpke_pbuf(stdout, "\thpke_prbuf2evp pub input", pubuf, pubuf_len);
    } else {
        printf("\thpke_prbuf2evp: no public value supplied\n");
    }
#endif
    if (prbuf == NULL || prbuf_len == 0 || retpriv == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hpke_kem_tab[kem_ind].Npriv == prbuf_len) {
        if (keytype == NULL) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        param_bld = OSSL_PARAM_BLD_new();
        if (param_bld == NULL) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (groupname != NULL
            && OSSL_PARAM_BLD_push_utf8_string(param_bld, "group",
                                               groupname, 0) != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (pubuf != NULL && pubuf_len > 0) {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", pubuf,
                                                 pubuf_len) != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else if (hpke_kem_id_nist_curve(kem_id) == 1) {
#ifndef OPENSSL_NO_EC
            /* need to calculate that public value, but we can:-) */
            groupnid = hpke_kem_tab[kem_ind].groupid;
            pubsize = hpke_kem_tab[kem_ind].Npk;
            memset(calc_pubuf, 0, calc_pubuf_len); /* keep asan happy */
            curve = EC_GROUP_new_by_curve_name(groupnid);
            if (curve == NULL) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            calc_priv = BN_bin2bn(prbuf, prbuf_len, NULL);
            if (calc_priv == NULL) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            calc_pub = EC_POINT_new(curve);
            if (calc_pub == NULL) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (EC_POINT_mul(curve, calc_pub, calc_priv, NULL, NULL,
                             NULL) != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if ((calc_pubuf_len = EC_POINT_point2oct(curve, calc_pub, form,
                                                     calc_pubuf, calc_pubuf_len,
                                                     NULL)) != pubsize) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", calc_pubuf,
                                                 calc_pubuf_len) != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
#else
            /* can't do that if no EC support compiled in:-( */
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
#endif
        }
        if (strlen(keytype) == 2 && !strcmp(keytype, "EC")) {
            priv = BN_bin2bn(prbuf, prbuf_len, NULL);
            if (priv == NULL) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv) != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld, "priv", prbuf,
                                                 prbuf_len) != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        params = OSSL_PARAM_BLD_to_param(param_bld);
        if (params == NULL) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ctx = EVP_PKEY_CTX_new_from_name(libctx, keytype, propq);
        if (ctx == NULL) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_fromdata_init(ctx) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_fromdata(ctx, &lpriv, EVP_PKEY_KEYPAIR, params) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (lpriv == NULL) {
        /* check PEM decode - that might work :-) */
        BIO *bfp = BIO_new(BIO_s_mem());

        if (bfp == NULL) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        BIO_write(bfp, prbuf, prbuf_len);
        if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
            BIO_free_all(bfp);
            bfp = NULL;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (bfp != NULL) {
            BIO_free_all(bfp);
            bfp = NULL;
        }
        if (lpriv == NULL) {
            /* if not done, prepend/append PEM header/footer and try again */
            memcpy(hf_prbuf, PEM_PRIVATEHEADER, strlen(PEM_PRIVATEHEADER));
            hf_prbuf_len += strlen(PEM_PRIVATEHEADER);
            memcpy(hf_prbuf + hf_prbuf_len, prbuf, prbuf_len);
            hf_prbuf_len += prbuf_len;
            memcpy(hf_prbuf + hf_prbuf_len, PEM_PRIVATEFOOTER,
                   strlen(PEM_PRIVATEFOOTER));
            hf_prbuf_len += strlen(PEM_PRIVATEFOOTER);
            bfp = BIO_new(BIO_s_mem());
            if (bfp == NULL) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            BIO_write(bfp, hf_prbuf, hf_prbuf_len);
            if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
                BIO_free_all(bfp);
                bfp = NULL;
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            BIO_free_all(bfp);
            bfp = NULL;
        }
    }
    if (lpriv == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *retpriv = lpriv;
    erv = 1;

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    if (erv == 1) {
        printf("\thpke_prbuf2evp success\n");
    } else {
        printf("\thpke_prbuf2evp FAILED at %d\n", erv);
    }
#endif
#ifndef OPENSSL_NO_EC
    BN_free(calc_priv);
    EC_POINT_free(calc_pub);
    EC_GROUP_free(curve);
#endif
    BN_free(priv);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    return erv;
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not 1 otherwise
 */
static int hpke_suite_check(OSSL_HPKE_SUITE suite)
{
    /*
     * Check that the fields of the suite are each
     * implemented here
     */
    int kem_ok = 0;
    int kdf_ok = 0;
    int aead_ok = 0;
    int ind = 0;
    int nkems = OSSL_NELEM(hpke_kem_tab);
    int nkdfs = OSSL_NELEM(hpke_kdf_tab);
    int naeads = OSSL_NELEM(hpke_aead_tab);

    /* check KEM */
    for (ind = 0; ind != nkems; ind++) {
        if (suite.kem_id == hpke_kem_tab[ind].kem_id) {
            kem_ok = 1;
            break;
        }
    }

    /* check kdf */
    for (ind = 0; ind != nkdfs; ind++) {
        if (suite.kdf_id == hpke_kdf_tab[ind].kdf_id) {
            kdf_ok = 1;
            break;
        }
    }

    /* check aead */
    for (ind = 0; ind != naeads; ind++) {
        if (suite.aead_id == hpke_aead_tab[ind].aead_id) {
            aead_ok = 1;
            break;
        }
    }

    if (kem_ok == 1 && kdf_ok == 1 && aead_ok == 1)
        return 1;
    return 0;
}

#ifdef HAPPYKEY
/*
 * @brief Internal HPKE single-shot encryption function
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
 * @param extsenderpriv has the handle for the sender private key
 * @param expseclen is the length of the exportersecret buffer
 * @param expsec is the exporter secret
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpub is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not 1 for error
 */
#ifdef TESTVECTORS
static int hpke_enc_int(OSSL_LIB_CTX *libctx, const char *propq,
                        unsigned int mode, OSSL_HPKE_SUITE suite,
                        const char *pskid,
                        size_t psklen, const unsigned char *psk,
                        size_t publen, const unsigned char *pub,
                        size_t authprivlen, const unsigned char *authpriv,
                        EVP_PKEY *authpriv_evp,
                        size_t clearlen, const unsigned char *clear,
                        size_t aadlen, const unsigned char *aad,
                        size_t infolen, const unsigned char *info,
                        size_t seqlen, const unsigned char *seq,
                        EVP_PKEY *extsenderpriv,
                        size_t rawsenderprivlen,
                        const unsigned char *rawsenderpriv,
                        size_t *expseclen, unsigned char *expsec,
                        size_t *senderpublen, unsigned char *senderpub,
                        size_t *cipherlen, unsigned char *cipher, void *tv)
#else
static int hpke_enc_int(OSSL_LIB_CTX *libctx, const char *propq,
                        unsigned int mode, OSSL_HPKE_SUITE suite,
                        const char *pskid,
                        size_t psklen, const unsigned char *psk,
                        size_t publen, const unsigned char *pub,
                        size_t authprivlen, const unsigned char *authpriv,
                        EVP_PKEY *authpriv_evp,
                        size_t clearlen, const unsigned char *clear,
                        size_t aadlen, const unsigned char *aad,
                        size_t infolen, const unsigned char *info,
                        size_t seqlen, const unsigned char *seq,
                        EVP_PKEY *extsenderpriv,
                        size_t rawsenderprivlen,
                        const unsigned char *rawsenderpriv,
                        size_t *expseclen, unsigned char *expsec,
                        size_t *senderpublen, unsigned char *senderpub,
                        size_t *cipherlen, unsigned char *cipher)
#endif

{
    int erv = 1; /* Our error return value - 1 is success */
    int evpcaller = 0;
    int rawcaller = 0;
#if defined(TESTVECTORS)
    hpke_tv_t *ltv = (hpke_tv_t *)tv;
#endif
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *skI = NULL;
    size_t shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t enclen = 0;
    unsigned char *enc = NULL;
    size_t ks_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char ks_context[OSSL_HPKE_MAXSIZE];
    size_t secretlen = OSSL_HPKE_MAXSIZE;
    unsigned char secret[OSSL_HPKE_MAXSIZE];
    size_t psk_hashlen = OSSL_HPKE_MAXSIZE;
    unsigned char psk_hash[OSSL_HPKE_MAXSIZE];
    size_t noncelen = OSSL_HPKE_MAXSIZE;
    unsigned char nonce[OSSL_HPKE_MAXSIZE];
    size_t keylen = OSSL_HPKE_MAXSIZE;
    unsigned char key[OSSL_HPKE_MAXSIZE];
    size_t exporterseclen = OSSL_HPKE_MAXSIZE;
    unsigned char exportersec[OSSL_HPKE_MAXSIZE];
    size_t mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;
    uint16_t aead_ind = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if ((erv = hpke_mode_check(mode)) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((erv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((erv = hpke_suite_check(suite)) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Depending on who called us, we may want to generate this key pair
     * or we may have had it handed to us via extsender inputs
     */
    if (extsenderpriv != NULL) {
        evpcaller = 1;
    }
    if (extsenderpriv == NULL
        && rawsenderprivlen > 0 && rawsenderpriv != NULL) {
        rawcaller = 1;
    }
    if (evpcaller == 0 && rawcaller == 0
        && (pub == NULL || clear == NULL
            || senderpublen == NULL || senderpub == NULL
            || cipherlen == NULL || cipher == NULL)) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (evpcaller
        && (pub == NULL || clear == NULL
            || senderpublen == NULL || senderpub == NULL
            || extsenderpriv == NULL || !cipherlen || cipher == NULL)) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (rawcaller
        && (pub == NULL || clear == NULL
            || rawsenderpriv == NULL || !cipherlen || cipher == NULL)) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_AUTH || mode == OSSL_HPKE_MODE_PSKAUTH)
        &&
        ((authpriv == NULL || authprivlen == 0) && (authpriv_evp == NULL))) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH)
        && (psk == NULL || !psklen || pskid == NULL)) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
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
     */

    /* step 0. Initialise peer's key from string */
    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkR = EVP_PKEY_new_raw_nist_public_key(libctx, propq,
                                               hpke_kem_tab[kem_ind].groupid,
                                               hpke_kem_tab[kem_ind].groupname,
                                               pub, publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key_ex(libctx,
                                             hpke_kem_tab[kem_ind].keytype,
                                             propq, pub, publen);
    }
    if (pkR == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* step 1. generate or import sender's key pair: skE, pkE */
    if (!evpcaller && !rawcaller) {
        pctx = EVP_PKEY_CTX_new(pkR, NULL);
        if (pctx == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
#ifdef TESTVECTORS
        if (ltv) {
            /* Read encap DH private from tv, instead of new key pair */
            unsigned char *bin_skE = NULL;
            size_t bin_skElen = 0;
            unsigned char *bin_pkE = NULL;
            size_t bin_pkElen = 0;

            if (hpke_kem_id_check(ltv->kem_id) != 1) {
                erv = 0;
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            erv = hpke_ah_decode(strlen(ltv->skEm), ltv->skEm,
                                 &bin_skElen, &bin_skE);
            if (erv != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            erv = hpke_ah_decode(strlen(ltv->pkEm), ltv->pkEm,
                                 &bin_pkElen, &bin_pkE);
            if (erv != 1) {
                OPENSSL_free(bin_skE);
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (hpke_prbuf2evp(libctx, propq, ltv->kem_id, bin_skE, bin_skElen,
                               bin_pkE, bin_pkElen, &pkE) != 1) {
                OPENSSL_free(bin_skE);
                OPENSSL_free(bin_pkE);
                erv = 0;
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            OPENSSL_free(bin_skE);
            OPENSSL_free(bin_pkE);
        } else {
            if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
                erv = 0;
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
#else
        if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
#endif
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
    } else if (evpcaller) {
        pkE = extsenderpriv;
    } else if (rawcaller) {
        erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, rawsenderpriv,
                             rawsenderprivlen, NULL, 0, &pkE);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (pkE == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (evpcaller == 1 || rawcaller == 1) {
        /* stash relevant public key for caller */
        mypublen = EVP_PKEY_get1_encoded_public_key(pkE, &mypub);
        if (mypub == NULL || mypublen == 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (mypublen > *senderpublen) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(senderpub, mypub, mypublen);
        *senderpublen = mypublen;
        OPENSSL_free(mypub);
        mypub = NULL;
        mypublen = 0;
    }

    /* step 2 run DH KEM to get dh */
    enclen = EVP_PKEY_get1_encoded_public_key(pkE, &enc);
    if (enc == NULL || enclen == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* load auth key pair if using an auth mode */
    if (mode == OSSL_HPKE_MODE_AUTH || mode == OSSL_HPKE_MODE_PSKAUTH) {
#ifdef TESTVECTORS
        if (ltv) {
            unsigned char *bin_pkS = NULL;
            size_t bin_pkSlen = 0;

            erv = hpke_ah_decode(strlen(ltv->pkSm), ltv->pkSm,
                                 &bin_pkSlen, &bin_pkS);
            if (erv != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, authpriv,
                                 authprivlen, bin_pkS, bin_pkSlen, &skI);
        } else {
            erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, authpriv,
                                 authprivlen, pub, publen, &skI);
        }
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
#else
        if (authpriv_evp != NULL) {
            skI = authpriv_evp;
        } else {
            erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, authpriv,
                                 authprivlen, pub, publen, &skI);
            if (erv != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
#endif
        if (skI == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mypublen = EVP_PKEY_get1_encoded_public_key(skI, &mypub);
        if (mypub == NULL || mypublen == 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    erv = hpke_do_kem(libctx, propq, 1, suite, pkE, enclen, enc, pkR,
                      publen, pub, skI, mypublen, mypub,
                      &shared_secret, &shared_secretlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_free(mypub);
    mypub = NULL;

    /* step 3. create context buffer starting with key_schedule_context */
    memset(ks_context, 0, sizeof(ks_context));
    ks_context[0] = (unsigned char)(mode % 256);
    ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSKIDHASH_LABEL,
                       strlen(OSSL_HPKE_PSKIDHASH_LABEL),
                       (unsigned char *)pskid, pskidlen,
                       ks_context + 1, &halflen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ks_contextlen -= halflen;
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_INFOHASH_LABEL,
                       strlen(OSSL_HPKE_INFOHASH_LABEL),
                       (unsigned char *)info, infolen,
                       ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ks_contextlen += 1 + halflen;
    /* step 4. extracts and expands as needed */
#ifdef TESTVECTORS
    hpke_test_expand_extract();
#endif
    /* Extract secret and Expand variously...  */
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSK_HASH_LABEL,
                       strlen(OSSL_HPKE_PSK_HASH_LABEL),
                       psk, psklen, psk_hash, &psk_hashlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tpsk_hash", psk_hash, psk_hashlen);
#endif
    kdf_ind = kdf_iana2index(suite.kdf_id);
    if (kdf_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    secretlen = hpke_kdf_tab[kdf_ind].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       shared_secret, shared_secretlen,
                       OSSL_HPKE_SECRET_LABEL, strlen(OSSL_HPKE_SECRET_LABEL),
                       psk, psklen, secret, &secretlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    noncelen = hpke_aead_tab[aead_ind].Nn;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_NONCE_LABEL, strlen(OSSL_HPKE_NONCE_LABEL),
                      ks_context, ks_contextlen, noncelen, nonce, &noncelen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (noncelen != hpke_aead_tab[aead_ind].Nn) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (seq != NULL && seqlen > 0) { /* XOR sequence with nonce as needed */
        size_t sind;
        unsigned char cv;
        if (seqlen > noncelen) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }
    keylen = hpke_aead_tab[aead_ind].Nk;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_KEY_LABEL, strlen(OSSL_HPKE_KEY_LABEL),
                      ks_context, ks_contextlen, keylen, key, &keylen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    exporterseclen = hpke_kdf_tab[kdf_ind].Nh;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_EXP_LABEL, strlen(OSSL_HPKE_EXP_LABEL),
                      ks_context, ks_contextlen,
                      exporterseclen, exportersec, &exporterseclen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* If exportersec was requested then provide that if enough space */
    if (expsec != NULL && expseclen != NULL) {
        if (*expseclen < exporterseclen) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        *expseclen = exporterseclen;
        memcpy(expsec, exportersec, exporterseclen);
    }
    /* step 5. call the AEAD */
    erv = hpke_aead_enc(libctx, propq, suite, key, keylen, nonce, noncelen,
                        aad, aadlen, clear, clearlen, cipher, cipherlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!evpcaller && !rawcaller) { /* finish up */
        if (enclen > *senderpublen) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(senderpub, enc, enclen);
        *senderpublen = enclen;
    }

err:

#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
           hpke_mode_strtab[mode], mode, hpke_kem_strtab[kem_ind], suite.kem_id,
           hpke_kdf_strtab[kdf_ind], suite.kdf_id,
           hpke_aead_strtab[aead_ind], suite.aead_id);
    if (pkE) {
        pblen = EVP_PKEY_get1_encoded_public_key(pkE, &pbuf);
        hpke_pbuf(stdout, "\tpkE", pbuf, pblen);
        OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkE is NULL\n");
    }
    if (pkR) {
        pblen = EVP_PKEY_get1_encoded_public_key(pkR, &pbuf);
        hpke_pbuf(stdout, "\tpkR", pbuf, pblen);
        OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkR is NULL\n");
    }
    if (skI) {
        pblen = EVP_PKEY_get1_encoded_public_key(skI, &pbuf);
        hpke_pbuf(stdout, "\tskI", pbuf, pblen);
        OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tskI is NULL\n");
    }
    hpke_pbuf(stdout, "\tshared_secret", shared_secret, shared_secretlen);
    hpke_pbuf(stdout, "\tks_context", ks_context, ks_contextlen);
    hpke_pbuf(stdout, "\tsecret", secret, secretlen);
    hpke_pbuf(stdout, "\tenc", enc, enclen);
    hpke_pbuf(stdout, "\tinfo", info, infolen);
    hpke_pbuf(stdout, "\taad", aad, aadlen);
    hpke_pbuf(stdout, "\tseq", seq, seqlen);
    hpke_pbuf(stdout, "\tnonce", nonce, noncelen);
    hpke_pbuf(stdout, "\tkey", key, keylen);
    hpke_pbuf(stdout, "\texportersec", exportersec, exporterseclen);
    hpke_pbuf(stdout, "\tplaintext", clear, clearlen);
    if (*cipherlen != OSSL_HPKE_MAXSIZE) {
        hpke_pbuf(stdout, "\tciphertext", cipher, *cipherlen);
    } else {
        fprintf(stdout, "\tciphertext: probably not generated\n");
    }
    if (mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH) {
        fprintf(stdout, "\tpskid: %s\n", pskid);
        hpke_pbuf(stdout, "\tpsk", psk, psklen);
    }

#endif
    OPENSSL_free(mypub);
    BIO_free_all(bfp);
    EVP_PKEY_free(pkR);
    if (!evpcaller) { EVP_PKEY_free(pkE); }
    if (authpriv_evp == NULL)
        EVP_PKEY_free(skI);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(shared_secret);
    OPENSSL_free(enc);
    return erv;
}

/*
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
 * @param expseclen is the length of the exportersecret buffer
 * @param expsec is the exporter secret
 * @param clearlen length of the input buffer for cleartext
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_dec_int(OSSL_LIB_CTX *libctx, const char *propq,
                        unsigned int mode, OSSL_HPKE_SUITE suite,
                        const char *pskid,
                        size_t psklen, const unsigned char *psk,
                        size_t authpublen, const unsigned char *authpub,
                        size_t privlen, const unsigned char *priv,
                        EVP_PKEY *evppriv,
                        size_t enclen, const unsigned char *enc,
                        size_t cipherlen, const unsigned char *cipher,
                        size_t aadlen, const unsigned char *aad,
                        size_t infolen, const unsigned char *info,
                        size_t seqlen, const unsigned char *seq,
                        size_t *expseclen, unsigned char *expsec,
                        size_t *clearlen, unsigned char *clear)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *pkI = NULL;
    size_t shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t ks_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char ks_context[OSSL_HPKE_MAXSIZE];
    size_t secretlen = OSSL_HPKE_MAXSIZE;
    unsigned char secret[OSSL_HPKE_MAXSIZE];
    size_t noncelen = OSSL_HPKE_MAXSIZE;
    unsigned char nonce[OSSL_HPKE_MAXSIZE];
    size_t psk_hashlen = OSSL_HPKE_MAXSIZE;
    unsigned char psk_hash[OSSL_HPKE_MAXSIZE];
    size_t keylen = OSSL_HPKE_MAXSIZE;
    unsigned char key[OSSL_HPKE_MAXSIZE];
    size_t exporterseclen = OSSL_HPKE_MAXSIZE;
    unsigned char exportersec[OSSL_HPKE_MAXSIZE];
    size_t mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;
    uint16_t aead_ind = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if ((erv = hpke_mode_check(mode)) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((erv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((erv = hpke_suite_check(suite)) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((priv == NULL && evppriv == NULL)
        || !clearlen || clear == NULL || cipher == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_AUTH || mode == OSSL_HPKE_MODE_PSKAUTH)
        && (!authpub || authpublen == 0)) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH)
        && (psk == NULL || !psklen || pskid == NULL)) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

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
        pkE = EVP_PKEY_new_raw_nist_public_key(libctx, propq,
                                               hpke_kem_tab[kem_ind].
                                               groupid,
                                               hpke_kem_tab[kem_ind].
                                               groupname,
                                               enc, enclen);
    } else {
        pkE = EVP_PKEY_new_raw_public_key_ex(libctx,
                                             hpke_kem_tab[kem_ind].keytype,
                                             propq, enc, enclen);
    }
    if (pkE == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (authpublen != 0 && authpub != NULL) {
        if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
            pkI = EVP_PKEY_new_raw_nist_public_key(libctx, propq,
                                                   hpke_kem_tab[kem_ind].
                                                   groupid,
                                                   hpke_kem_tab[kem_ind].
                                                   groupname,
                                                   authpub, authpublen);
        } else {
            pkI = EVP_PKEY_new_raw_public_key_ex(libctx,
                                                 hpke_kem_tab[kem_ind].keytype,
                                                 propq, authpub, authpublen);
        }
        if (pkI == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    /* step 1. load decryptors private key */
    if (evppriv == NULL) {
        erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, priv, privlen,
                             NULL, 0, &skR);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (skR == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        skR = evppriv;
    }

    /* step 2 run DH KEM to get dh */
    mypublen = EVP_PKEY_get1_encoded_public_key(skR, &mypub);
    if (mypub == NULL || mypublen == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = hpke_do_kem(libctx, propq, 0, suite, skR, mypublen, mypub, pkE,
                      enclen, enc, pkI, authpublen, authpub,
                      &shared_secret, &shared_secretlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* step 3. create context buffer */
    memset(ks_context, 0, sizeof(ks_context));
    ks_context[0] = (unsigned char)(mode % 256);

    ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSKIDHASH_LABEL,
                       strlen(OSSL_HPKE_PSKIDHASH_LABEL),
                       (unsigned char *)pskid, pskidlen,
                       ks_context + 1, &halflen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef SUPERVERBOSE
    hpke_pbuf(stdout, "\tpskidhash", ks_context + 1, halflen);
#endif
    ks_contextlen -= halflen;
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_INFOHASH_LABEL,
                       strlen(OSSL_HPKE_INFOHASH_LABEL),
                       info, infolen,
                       ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef SUPERVERBOSE
    hpke_pbuf(stdout, "\tinfohash", ks_context + 1 + halflen, ks_contextlen);
#endif
    ks_contextlen += 1 + halflen;

    /* step 4. extracts and expands as needed */
    /* Extract secret and Expand variously...  */
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSK_HASH_LABEL,
                       strlen(OSSL_HPKE_PSK_HASH_LABEL),
                       psk, psklen,
                       psk_hash, &psk_hashlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tpsk_hash", psk_hash, psk_hashlen);
#endif
    kdf_ind = kdf_iana2index(suite.kdf_id);
    if (kdf_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    secretlen = hpke_kdf_tab[kdf_ind].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                       shared_secret, shared_secretlen,
                       OSSL_HPKE_SECRET_LABEL, strlen(OSSL_HPKE_SECRET_LABEL),
                       psk, psklen, secret, &secretlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    noncelen = hpke_aead_tab[aead_ind].Nn;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_NONCE_LABEL, strlen(OSSL_HPKE_NONCE_LABEL),
                      ks_context, ks_contextlen,
                      noncelen, nonce, &noncelen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (noncelen != hpke_aead_tab[aead_ind].Nn) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* XOR sequence with nonce as needed */
    if (seq != NULL && seqlen > 0) {
        size_t sind;
        unsigned char cv;

        if (seqlen > noncelen) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }
    keylen = hpke_aead_tab[aead_ind].Nk;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_KEY_LABEL, strlen(OSSL_HPKE_KEY_LABEL),
                      ks_context, ks_contextlen,
                      keylen, key, &keylen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    exporterseclen = hpke_kdf_tab[kdf_ind].Nh;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_EXP_LABEL, strlen(OSSL_HPKE_EXP_LABEL),
                      ks_context, ks_contextlen,
                      exporterseclen, exportersec, &exporterseclen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* If exportersec was requested then provide that if enough space */
    if (expsec != NULL && expseclen != NULL) {
        if (*expseclen < exporterseclen) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        *expseclen = exporterseclen;
        memcpy(expsec, exportersec, exporterseclen);
    }

    /* step 5. call the AEAD */
    erv = hpke_aead_dec(libctx, propq, suite, key, keylen,
                        nonce, noncelen, aad, aadlen,
                        cipher, cipherlen, clear, clearlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
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
        OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkE is NULL\n");
    }
    if (skR) {
        pblen = EVP_PKEY_get1_encoded_public_key(skR, &pbuf);
        hpke_pbuf(stdout, "\tpkR", pbuf, pblen);
        OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tpkR is NULL\n");
    }
    if (pkI) {
        pblen = EVP_PKEY_get1_encoded_public_key(pkI, &pbuf);
        hpke_pbuf(stdout, "\tpkI", pbuf, pblen);
        OPENSSL_free(pbuf);
    } else {
        fprintf(stdout, "\tskI is NULL\n");
    }
    hpke_pbuf(stdout, "\tshared_secret", shared_secret, shared_secretlen);
    hpke_pbuf(stdout, "\tks_context", ks_context, ks_contextlen);
    hpke_pbuf(stdout, "\tsecret", secret, secretlen);
    hpke_pbuf(stdout, "\texportersec", exportersec, exporterseclen);
    hpke_pbuf(stdout, "\tenc", enc, enclen);
    hpke_pbuf(stdout, "\tinfo", info, infolen);
    hpke_pbuf(stdout, "\taad", aad, aadlen);
    hpke_pbuf(stdout, "\tnonce", nonce, noncelen);
    hpke_pbuf(stdout, "\tkey", key, keylen);
    hpke_pbuf(stdout, "\tciphertext", cipher, cipherlen);
    if (mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH) {
        fprintf(stdout, "\tpskid: %s\n", pskid);
        hpke_pbuf(stdout, "\tpsk", psk, psklen);
    }
    if (*clearlen != OSSL_HPKE_MAXSIZE)
        hpke_pbuf(stdout, "\tplaintext", clear, *clearlen);
    else
        printf("clearlen = OSSL_HPKE_MAXSIZE, so decryption probably failed\n");
#endif
    BIO_free_all(bfp);
    if (evppriv == NULL) { EVP_PKEY_free(skR); }
    EVP_PKEY_free(pkE);
    EVP_PKEY_free(pkI);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(shared_secret);
    OPENSSL_free(mypub);
    return erv;
}

/*
 * @brief compare a buffer vs. the group order
 *
 * @param kemid specifies the group (HPKE KEM code-points)
 * @param buflen is the size of the buffer
 * @param buf is the buffer
 * @param res is returned as 0 for equal, -1 if buf < order, +1 if buf > order
 * @return 1 for good, other otherwise
 */
static int hpke_kg_comp2order(uint32_t kemid, size_t buflen,
                              unsigned char *buf, int *res)
{
    /*
     * P-256: ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
     * P-384: ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf
     *        581a0db248b0a77aecec196accc52973
     * P-521: 01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
     *        fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
     */
    BIGNUM *bufbn = NULL;
    BIGNUM *gorder = NULL;
    int cres = 0;
    unsigned char p256ord[] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    };
    unsigned char p384ord[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
        0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
        0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73
    };
    unsigned char p521ord[] = {
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
        0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
        0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
        0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
        0x64, 0x09
    };

    if (res == NULL || buf == NULL || buflen == 0) {
        return 0;
    }
    switch (kemid) {
    case OSSL_HPKE_KEM_ID_P256:
        gorder = BN_bin2bn(p256ord, sizeof(p256ord), NULL);
        break;
    case OSSL_HPKE_KEM_ID_P384:
        gorder = BN_bin2bn(p384ord, sizeof(p384ord), NULL);
        break;
    case OSSL_HPKE_KEM_ID_P521:
        gorder = BN_bin2bn(p521ord, sizeof(p521ord), NULL);
        break;
    default:
        return 0;
    }
    if (gorder == NULL) {
        return 0;
    }
    bufbn = BN_bin2bn(buf, buflen, NULL);
    if (bufbn == NULL) {
        return 0;
    }
    cres = BN_cmp(bufbn, gorder);
    *res = cres;
    BN_free(bufbn);
    BN_free(gorder);
    return 1;
}
#endif /* HAPPYKEY */
/*
 * @brief generate a key pair keeping private inside API
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key pointer
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg_evp(OSSL_LIB_CTX *libctx, const char *propq,
                       unsigned int mode, OSSL_HPKE_SUITE suite,
                       size_t ikmlen, const unsigned char *ikm,
                       size_t *publen, unsigned char *pub,
                       EVP_PKEY **priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    unsigned char *lpub = NULL;
    size_t lpublen = 0;
    uint16_t kem_ind = 0;
#ifndef HAPPYKEY
    OSSL_PARAM params[3], *p = params;
#else
    int cmp = 0;
#endif

    if (hpke_suite_check(suite) != 1)
        return 0;
    if (pub == NULL || publen == NULL || *publen == 0 || priv == NULL)
        return 0;
    if (ikmlen > 0 && ikm == NULL)
        return 0;
    if (ikmlen == 0 && ikm != NULL)
        return 0;
    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifndef HAPPYKEY
#ifdef SUPERVERBOSE
    printf("DHKEM KG for KEM %d\n", suite.kem_id);
#endif
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)hpke_kem_tab[kem_ind]
                                                .groupname, 0);
        pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, hpke_kem_tab[kem_ind].keytype,
                                          propq);
    }
    if (pctx == NULL
        || EVP_PKEY_keygen_init(pctx) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ikm != NULL) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM,
                                                 (char *)ikm, ikmlen);
    }
    *p = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_generate(pctx, &skR) <=0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#else

    /* setup generation of key pair */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        /* TODO: check this use of propq!!! */
        pctx = EVP_PKEY_CTX_new_from_name(libctx, hpke_kem_tab[kem_ind].keytype,
                                          (propq != NULL ? propq
                                           : hpke_kem_tab[kem_ind].groupname)
                                          );
        if (pctx == NULL
            || EVP_PKEY_paramgen_init(pctx) != 1
            || EVP_PKEY_keygen_init(pctx) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                   hpke_kem_tab[kem_ind].groupid
                                                   ) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (ikm != NULL) {
            /* deterministic generation for NIST curves */
            size_t tmplen = OSSL_HPKE_MAXSIZE;
            unsigned char tmp[OSSL_HPKE_MAXSIZE];
            size_t sklen = OSSL_HPKE_MAXSIZE;
            unsigned char sk[OSSL_HPKE_MAXSIZE];
            unsigned char counter = 0;

#ifdef SUPERVERBOSE
            printf("Deterministic KG for KEM %d\n", suite.kem_id);
#endif
            erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_KEM,
                               (const unsigned char *)"", 0,
                               OSSL_HPKE_DPK_LABEL, strlen(OSSL_HPKE_DPK_LABEL),
                               ikm, ikmlen, tmp, &tmplen);
            if (erv != 1) { goto err; }
            while (counter < 255) {
                erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_KEM,
                                  tmp, tmplen, OSSL_HPKE_CAND_LABEL,
                                  strlen(OSSL_HPKE_CAND_LABEL),
                                  &counter, 1, hpke_kem_tab[kem_ind].Npriv,
                                  sk, &sklen);
                if (erv != 1) {
                    memset(tmp, 0, sizeof(tmp));
                    goto err;
                }
                switch (suite.kem_id) {
                case OSSL_HPKE_KEM_ID_P256:
                case OSSL_HPKE_KEM_ID_P384:
                    /* nothing to do for those really */
                    break;
                case OSSL_HPKE_KEM_ID_P521:
                    /* mask as RFC requires */
                    sk[0] &= 0x01;
                    break;
                default:
                    memset(tmp, 0, sizeof(tmp));
                    goto err;
                }
                /* check sk vs. group order */
                if (hpke_kg_comp2order(suite.kem_id, sklen, sk, &cmp) != 1) {
                    goto err;
                }
                if (cmp == -1) { /* success! */
                    break;
                }
                counter++;
#ifdef SUPERVERBOSE
                printf("Incrememting det counter! (%d -> %d) for KEM 0x%2x\n",
                       counter - 1, counter, suite.kem_id);
#endif
            }
            if (counter == 255) {
                memset(tmp, 0, sizeof(tmp));
                goto err;
            }
#ifdef SUPERVERBOSE
            hpke_pbuf(stdout, "\tdeterministic sk", sk, sklen);
#endif
            erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, sk, sklen,
                                 NULL, 0, &skR);
            memset(sk, 0, sklen);
            memset(tmp, 0, sizeof(tmp));
            if (erv != 1) { goto err; }
        }
#ifdef SUPERVERBOSE
        else {
            printf("Random KG for KEM %d\n", suite.kem_id);
        }
#endif
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, hpke_kem_tab[kem_ind].keytype,
                                          propq);
        if (pctx == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (ikm != NULL) {
            /* deterministic generation for cfrg curves */
            size_t tmplen = OSSL_HPKE_MAXSIZE;
            unsigned char tmp[OSSL_HPKE_MAXSIZE];
            size_t sklen = OSSL_HPKE_MAXSIZE;
            unsigned char sk[OSSL_HPKE_MAXSIZE];

#ifdef SUPERVERBOSE
            printf("Deterministic KG for KEM %d\n", suite.kem_id);
#endif
            erv = hpke_extract(libctx, propq, suite, OSSL_HPKE_5869_MODE_KEM,
                               (const unsigned char *)"", 0,
                               OSSL_HPKE_DPK_LABEL, strlen(OSSL_HPKE_DPK_LABEL),
                               ikm, ikmlen, tmp, &tmplen);
            if (erv != 1) { goto err; }
            erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_KEM,
                              tmp, tmplen,
                              OSSL_HPKE_SK_LABEL, strlen(OSSL_HPKE_SK_LABEL),
                              NULL, 0,
                              hpke_kem_tab[kem_ind].Npriv,
                              sk, &sklen);
            if (erv != 1) {
                memset(tmp, 0, sizeof(tmp));
                goto err;
            }
#ifdef SUPERVERBOSE
            hpke_pbuf(stdout, "\tdeterministic sk", sk, sklen);
#endif
            erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, sk, sklen,
                                 NULL, 0, &skR);
            memset(sk, 0, sklen);
            memset(tmp, 0, sizeof(tmp));
            if (erv != 1) { goto err; }

        }
#ifdef SUPERVERBOSE
        else {
            printf("Random KG for KEM %d\n", suite.kem_id);
        }
#endif
    }
    /* generate sender's key pair */
    if (ikm == NULL) {
        /* randomly generate, deterministic done above */
        if (EVP_PKEY_generate(pctx, &skR) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
#endif // HAPPYKEY
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    lpublen = EVP_PKEY_get1_encoded_public_key(skR, &lpub);
    if (lpub == NULL || lpublen == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef SUPERVERBOSE
    hpke_pbuf(stdout, "\tkg_evp pub", lpub, lpublen);
#endif
    if (lpublen > *publen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *publen = lpublen;
    memcpy(pub, lpub, lpublen);
    *priv = skR;

err:
    if (erv != 1) { EVP_PKEY_free(skR); }
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(lpub);
    return erv;
}
#ifdef HAPPYKEY
/*
 * @brief generate a key pair
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg(OSSL_LIB_CTX *libctx, const char *propq,
                   unsigned int mode, OSSL_HPKE_SUITE suite,
                   size_t ikmlen, const unsigned char *ikm,
                   size_t *publen, unsigned char *pub,
                   size_t *privlen, unsigned char *priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY *skR = NULL;
    BIO *bfp = NULL;
    unsigned char lpriv[OSSL_HPKE_MAXSIZE];
    size_t lprivlen = 0;

    if (hpke_suite_check(suite) != 1)
        return 0;
    if (pub == NULL || priv == NULL)
        return 0;
    erv = hpke_kg_evp(libctx, propq, mode, suite, ikmlen, ikm,
                      publen, pub, &skR);
    if (erv != 1) {
        return erv;
    }
    bfp = BIO_new(BIO_s_mem());
    if (bfp == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!PEM_write_bio_PrivateKey(bfp, skR, NULL, NULL, 0, NULL, NULL)) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    lprivlen = BIO_read(bfp, lpriv, OSSL_HPKE_MAXSIZE);
    if (lprivlen <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (lprivlen > *privlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *privlen = lprivlen;
    memcpy(priv, lpriv, lprivlen);

err:
    EVP_PKEY_free(skR);
    BIO_free_all(bfp);
    return erv;
}
#endif

/*
 * @brief randomly pick a suite
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite is the result
 * @return 1 for success, otherwise failure
 *
 * If you change the structure of the various *_tab arrays
 * then this code will also need change.
 */
static int hpke_random_suite(OSSL_LIB_CTX *libctx,
                             const char *propq,
                             OSSL_HPKE_SUITE *suite)
{
    unsigned char rval = 0;
    int nkdfs = OSSL_NELEM(hpke_kdf_tab)-1;
    int naeads = OSSL_NELEM(hpke_aead_tab)-1;
    int nkems = OSSL_NELEM(hpke_kem_tab)-1;

    /* random kem */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), OSSL_HPKE_RSTRENGTH) <= 0)
        return 0;
    suite->kem_id = hpke_kem_tab[(rval % nkems + 1)].kem_id;

    /* random kdf */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), OSSL_HPKE_RSTRENGTH) <= 0)
        return 0;
    suite->kdf_id = hpke_kdf_tab[(rval % nkdfs + 1)].kdf_id;

    /* random aead */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), OSSL_HPKE_RSTRENGTH) <= 0)
        return 0;
    suite->aead_id = hpke_aead_tab[(rval % naeads + 1)].aead_id;
    return 1;
}

/*
 * @brief return a (possibly) random suite, public key, ciphertext for GREASErs
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite-in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param ciphertext buffer with random value of the appropriate length
 * @param ciphertext_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
static int hpke_good4grease(OSSL_LIB_CTX *libctx, const char *propq,
                            OSSL_HPKE_SUITE *suite_in,
                            OSSL_HPKE_SUITE *suite,
                            unsigned char *pub,
                            size_t *pub_len,
                            unsigned char *ciphertext,
                            size_t ciphertext_len)
{
    OSSL_HPKE_SUITE chosen;
    int crv = 0;
    int erv = 0;
    size_t plen = 0;
    uint16_t kem_ind = 0;
#ifdef SUPERVERBOSE
    uint16_t aead_ind = 0;
    uint16_t kdf_ind = 0;
#endif

    if (pub == NULL || !pub_len
        || ciphertext == NULL || !ciphertext_len || suite == NULL)
        return 0;
    if (suite_in == NULL) {
        /* choose a random suite */
        crv = hpke_random_suite(libctx, propq, &chosen);
        if (crv != 1)
            return crv;
    } else {
        chosen = *suite_in;
    }
    kem_ind = kem_iana2index(chosen.kem_id);
    if (kem_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef SUPERVERBOSE
    aead_ind = aead_iana2index(chosen.aead_id);
    if (aead_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    kdf_ind = kdf_iana2index(chosen.kdf_id);
    if (kdf_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    printf("GREASEy suite before check:\n\tkem: %s (%d)," \
           " kdf: %s (%d), aead: %s (%d)\n",
           hpke_kem_strtab[kem_ind], chosen.kem_id,
           hpke_kdf_strtab[kdf_ind], chosen.kdf_id,
           hpke_aead_strtab[aead_ind], chosen.aead_id);
#endif
    if ((crv = hpke_suite_check(chosen)) != 1)
        return 0;
    *suite = chosen;
    /* publen */
    plen = hpke_kem_tab[kem_ind].Npk;
    if (plen > *pub_len)
        return 0;
    if (RAND_bytes_ex(libctx, pub, plen, OSSL_HPKE_RSTRENGTH) <= 0)
        return 0;
    *pub_len = plen;
    if (RAND_bytes_ex(libctx, ciphertext, ciphertext_len,
                      OSSL_HPKE_RSTRENGTH) <= 0)
        return 0;
#ifdef SUPERVERBOSE
    printf("GREASEy suite:\n\tkem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
           hpke_kem_strtab[kem_ind], chosen.kem_id,
           hpke_kdf_strtab[kdf_ind], chosen.kdf_id,
           hpke_aead_strtab[aead_ind], chosen.aead_id);
    hpke_pbuf(stdout, "GREASEy public", pub, *pub_len);
    hpke_pbuf(stdout, "GREASEy cipher", ciphertext, ciphertext_len);
#endif
    return 1;
err:
    return erv;
}

/*
 * @brief string matching for suites
 */
#if defined(_WIN32)
# define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !_stricmp(inp, known))
#else
# define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !strcasecmp(inp, known))
#endif

/*
 * @brief map a string to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
static int hpke_str2suite(const char *suitestr, OSSL_HPKE_SUITE *suite)
{
    uint16_t kem = 0, kdf = 0, aead = 0;
    char *st = NULL;
    char *instrcp = NULL;
    size_t inplen = 0;
    int labels = 0;

    if (suitestr == NULL || suite == NULL)
        return 0;
    /* See if it contains a mix of our strings and numbers  */
    inplen = OPENSSL_strnlen(suitestr, OSSL_HPKE_MAX_SUITESTR);
    if (inplen >= OSSL_HPKE_MAX_SUITESTR)
        return 0;
    instrcp = OPENSSL_strndup(suitestr, inplen);
    st = strtok(instrcp, ",");
    if (st == NULL) {
        OPENSSL_free(instrcp);
        return 0;
    }
    while (st != NULL && ++labels <= 3) {
        /* check if string is known or number and if so handle appropriately */
        if (kem == 0) {
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_P256)) {
                kem = OSSL_HPKE_KEM_ID_P256;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_P384)) {
                kem = OSSL_HPKE_KEM_ID_P384;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_P521)) {
                kem = OSSL_HPKE_KEM_ID_P521;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_X25519)) {
                kem = OSSL_HPKE_KEM_ID_X25519;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_X448)) {
                kem = OSSL_HPKE_KEM_ID_X448;
            }
            if (HPKE_MSMATCH(st, "0x10")) { kem = OSSL_HPKE_KEM_ID_P256; }
            if (HPKE_MSMATCH(st, "16")) { kem = OSSL_HPKE_KEM_ID_P256; }
            if (HPKE_MSMATCH(st, "0x11")) { kem = OSSL_HPKE_KEM_ID_P384; }
            if (HPKE_MSMATCH(st, "17")) { kem = OSSL_HPKE_KEM_ID_P384; }
            if (HPKE_MSMATCH(st, "0x12")) { kem = OSSL_HPKE_KEM_ID_P521; }
            if (HPKE_MSMATCH(st, "18")) { kem = OSSL_HPKE_KEM_ID_P521; }
            if (HPKE_MSMATCH(st, "0x20")) { kem = OSSL_HPKE_KEM_ID_X25519; }
            if (HPKE_MSMATCH(st, "32")) { kem = OSSL_HPKE_KEM_ID_X25519; }
            if (HPKE_MSMATCH(st, "0x21")) { kem = OSSL_HPKE_KEM_ID_X448; }
            if (HPKE_MSMATCH(st, "33")) { kem = OSSL_HPKE_KEM_ID_X448; }
        } else if (kem != 0 && kdf == 0) {
            if (HPKE_MSMATCH(st, OSSL_HPKE_KDFSTR_256)) { kdf = 1; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KDFSTR_384)) { kdf = 2; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KDFSTR_512)) { kdf = 3; }
            if (HPKE_MSMATCH(st, "0x01")) { kdf = 1; }
            if (HPKE_MSMATCH(st, "0x02")) { kdf = 2; }
            if (HPKE_MSMATCH(st, "0x03")) { kdf = 3; }
            if (HPKE_MSMATCH(st, "0x1")) { kdf = 1; }
            if (HPKE_MSMATCH(st, "0x2")) { kdf = 2; }
            if (HPKE_MSMATCH(st, "0x3")) { kdf = 3; }
            if (HPKE_MSMATCH(st, "1")) { kdf = 1; }
            if (HPKE_MSMATCH(st, "2")) { kdf = 2; }
            if (HPKE_MSMATCH(st, "3")) { kdf = 3; }
        } else if (kem != 0 && kdf != 0 && aead == 0) {
            if (HPKE_MSMATCH(st, OSSL_HPKE_AEADSTR_AES128GCM)) { aead = 1; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_AEADSTR_AES256GCM)) { aead = 2; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_AEADSTR_CP)) { aead = 3; }
            if (HPKE_MSMATCH(st, "0x01")) { aead = 1; }
            if (HPKE_MSMATCH(st, "0x02")) { aead = 2; }
            if (HPKE_MSMATCH(st, "0x03")) { aead = 3; }
            if (HPKE_MSMATCH(st, "0x1")) { aead = 1; }
            if (HPKE_MSMATCH(st, "0x2")) { aead = 2; }
            if (HPKE_MSMATCH(st, "0x3")) { aead = 3; }
            if (HPKE_MSMATCH(st, "1")) { aead = 1; }
            if (HPKE_MSMATCH(st, "2")) { aead = 2; }
            if (HPKE_MSMATCH(st, "3")) { aead = 3; }
        }
        st = strtok(NULL, ",");
    }
    OPENSSL_free(instrcp);
    if ((st != NULL && labels > 3) || kem == 0 || kdf == 0 || aead == 0) {
        return 0;
    }
    suite->kem_id = kem;
    suite->kdf_id = kdf;
    suite->aead_id = aead;
    return 1;
}

/*
 * @brief tell the caller how big the cipertext will be
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who knows what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given suite.
 *
 * @param suite is the suite to be used
 * @param enclen points to what'll be enc length
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
static int hpke_expansion(OSSL_HPKE_SUITE suite,
                          size_t *enclen,
                          size_t clearlen,
                          size_t *cipherlen)
{
#ifdef HAPPYKEY
    int erv = 1;
#endif
    uint16_t aead_ind = 0;
    uint16_t kem_ind = 0;

    if (cipherlen == NULL || enclen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (hpke_suite_check(suite) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *cipherlen = clearlen + hpke_aead_tab[aead_ind].taglen;
    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *enclen = hpke_kem_tab[kem_ind].Nenc;
    return 1;
}

static int hpke_seq2buf(uint64_t seq, unsigned char *buf, size_t blen)
{
#ifdef HAPPYKEY
    int erv = 1;
#endif
    uint64_t nbo_seq = 0;
    size_t nbo_seq_len = sizeof(nbo_seq);

    if (nbo_seq_len > 12 || blen < nbo_seq_len) {
        /* it'll be some time before we have such a wide int:-) */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memset(buf, 0, blen);
    nbo_seq = htonl(seq);
    memcpy(buf + blen - nbo_seq_len, &nbo_seq, nbo_seq_len);
    return nbo_seq_len;
}

#ifndef HAPPYKEY
static int hpke_encap(OSSL_HPKE_CTX *ctx, unsigned char *enc, size_t *enclen,
                      const unsigned char *pub, size_t publen)
{
    int erv = 1;
    OSSL_PARAM params[3], *p = params;
    size_t lsslen = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkR = NULL;
    int kem_ind = 0;

    if (ctx == NULL || enc == NULL || enclen == NULL || *enclen == 0
        || pub == NULL || publen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
        printf("\tbad input\n");
#endif
        return 0;
    }
    kem_ind = kem_iana2index(ctx->suite.kem_id);
    if (kem_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hpke_kem_id_nist_curve(ctx->suite.kem_id) == 1) {
        pkR = EVP_PKEY_new_raw_nist_public_key(ctx->libctx, ctx->propq,
                                               hpke_kem_tab[kem_ind].groupid,
                                               hpke_kem_tab[kem_ind].groupname,
                                               pub, publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key_ex(ctx->libctx,
                                             hpke_kem_tab[kem_ind].keytype,
                                             ctx->propq, pub, publen);
    }
    if (pkR == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, pkR, ctx->propq);
    if (pctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                            OSSL_KEM_PARAM_OPERATION_DHKEM,
                                            0);
    if (ctx->ikme != NULL) {
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
        hpke_pbuf(stdout, "\tikme", ctx->ikme, sizeof(ctx->ikme));
#endif
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
                                                 ctx->ikme, ctx->ikmelen);
    }
    *p = OSSL_PARAM_construct_end();
    if (ctx->mode == OSSL_HPKE_MODE_AUTH
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (EVP_PKEY_auth_encapsulate_init(pctx, ctx->authpriv,
                                           params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        if (EVP_PKEY_encapsulate_init(pctx, params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    erv = EVP_PKEY_encapsulate(pctx, NULL, enclen, NULL, &lsslen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ctx->shared_secret = OPENSSL_malloc(lsslen);
    if (ctx->shared_secret == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ctx->shared_secretlen = lsslen;
    erv = EVP_PKEY_encapsulate(pctx, enc, enclen,
                               ctx->shared_secret,
                               &ctx->shared_secretlen);
    if (erv != 1) {
        ctx->shared_secretlen = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tenc", enc, *enclen);
    hpke_pbuf(stdout, "\tshared_secret", ctx->shared_secret,
              ctx->shared_secretlen);
#endif
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkR);
    return erv;
}

static int hpke_decap(OSSL_HPKE_CTX *ctx,
                      const unsigned char *enc, size_t enclen,
                      EVP_PKEY *priv)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *spub = NULL;
    OSSL_PARAM params[3], *p = params;
    size_t lsslen;
    unsigned char lss[OSSL_HPKE_MAXSIZE];

    if (ctx == NULL || enc == NULL || enclen == 0 || priv == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, priv, ctx->propq);
    if (pctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                            OSSL_KEM_PARAM_OPERATION_DHKEM,
                                            0);
    *p = OSSL_PARAM_construct_end();
    if (ctx->mode == OSSL_HPKE_MODE_AUTH
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        int kem_ind = 0;

        kem_ind = kem_iana2index(ctx->suite.kem_id);
        if (kem_ind == 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (hpke_kem_id_nist_curve(ctx->suite.kem_id) == 1) {
            spub = EVP_PKEY_new_raw_nist_public_key(ctx->libctx, ctx->propq,
                                                    hpke_kem_tab[kem_ind].
                                                    groupid,
                                                    hpke_kem_tab[kem_ind].
                                                    groupname,
                                                    ctx->authpub,
                                                    ctx->authpublen);
        } else {
            spub = EVP_PKEY_new_raw_public_key_ex(ctx->libctx,
                                                  hpke_kem_tab[kem_ind].keytype,
                                                  ctx->propq,
                                                  ctx->authpub,
                                                  ctx->authpublen);
        }
        if (spub == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_auth_decapsulate_init(pctx, spub, params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        if (EVP_PKEY_decapsulate_init(pctx, params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    erv = EVP_PKEY_decapsulate(pctx, NULL, &lsslen, enc, enclen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (lsslen > OSSL_HPKE_MAXSIZE) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = EVP_PKEY_decapsulate(pctx, lss, &lsslen, enc, enclen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    OPENSSL_free(ctx->shared_secret); /* in case of 2nd call */
    ctx->shared_secret = OPENSSL_malloc(lsslen);
    if (ctx->shared_secret == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ctx->shared_secretlen = lsslen;
    memcpy(ctx->shared_secret, lss, lsslen);

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    hpke_pbuf(stdout, "\tenc", enc, enclen);
    hpke_pbuf(stdout, "\tshared_secret", ctx->shared_secret,
              ctx->shared_secretlen);
#endif
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(spub);
    OPENSSL_cleanse(lss, sizeof(lss));
    return erv;
}

static int hpke_do_rest(OSSL_HPKE_CTX *ctx, int do_enc,
                        unsigned char *ct, size_t *ctlen,
                        unsigned char *pt, size_t *ptlen,
                        const unsigned char *info, size_t infolen,
                        const unsigned char *aad, size_t aadlen)
{
    int erv = 1;
    size_t ks_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char ks_context[OSSL_HPKE_MAXSIZE];
    size_t halflen = 0;
    size_t pskidlen = 0;
    size_t psk_hashlen = OSSL_HPKE_MAXSIZE;
    unsigned char psk_hash[OSSL_HPKE_MAXSIZE];
    int kem_ind = 0;
    int kdf_ind = 0;
    int aead_ind = 0;
    size_t secretlen = OSSL_HPKE_MAXSIZE;
    unsigned char secret[OSSL_HPKE_MAXSIZE];
    size_t noncelen = OSSL_HPKE_MAXSIZE;
    unsigned char nonce[OSSL_HPKE_MAXSIZE];
    unsigned char seqbuf[12];
    size_t seqlen = 0;
    size_t keylen = OSSL_HPKE_MAXSIZE;
    unsigned char key[OSSL_HPKE_MAXSIZE];
    EVP_KDF_CTX *kctx = NULL;
    unsigned char suitebuf[6];
    const char *mdname = NULL;

    if ((kem_ind = kem_iana2index(ctx->suite.kem_id)) == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((aead_ind = aead_iana2index(ctx->suite.aead_id)) == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((kdf_ind = kdf_iana2index(ctx->suite.kdf_id)) == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    mdname = hpke_kdf_tab[kdf_ind].mdname;
    kctx = ossl_kdf_ctx_create("HKDF", mdname, ctx->libctx, ctx->propq);
    if (kctx == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* create key schedule context */
    memset(ks_context, 0, sizeof(ks_context));
    ks_context[0] = (unsigned char)(ctx->mode % 256);
    ks_contextlen--; /* remaining space */
    halflen = hpke_kdf_tab[kdf_ind].Nh;
    if ((2 * halflen) > ks_contextlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    pskidlen = (ctx->psk == NULL ? 0 : strlen(ctx->pskid));
    /* mode == FULL as per RFC9180 sec 5.1 */
    suitebuf[0] = ctx->suite.kem_id / 256;
    suitebuf[1] = ctx->suite.kem_id % 256;
    suitebuf[2] = ctx->suite.kdf_id / 256;
    suitebuf[3] = ctx->suite.kdf_id % 256;
    suitebuf[4] = ctx->suite.aead_id / 256;
    suitebuf[5] = ctx->suite.aead_id % 256;

    erv = ossl_hpke_labeled_extract(kctx,
                                    ks_context + 1, halflen,
                                    NULL, 0,
                                    OSSL_HPKE_SEC51LABEL,
                                    suitebuf, 6,
                                    OSSL_HPKE_PSKIDHASH_LABEL,
                                    (unsigned char *)ctx->pskid,
                                    pskidlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = ossl_hpke_labeled_extract(kctx,
                                    ks_context + 1 + halflen, halflen,
                                    NULL, 0,
                                    OSSL_HPKE_SEC51LABEL,
                                    suitebuf, 6,
                                    OSSL_HPKE_INFOHASH_LABEL,
                                    (unsigned char *)info, infolen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ks_contextlen = 1 + 2 * halflen;
    /* Extract and Expand variously...  */
    psk_hashlen = halflen;
    erv = ossl_hpke_labeled_extract(kctx,
                                    psk_hash, psk_hashlen,
                                    NULL, 0,  /* salt */
                                    OSSL_HPKE_SEC51LABEL, /* protocol label */
                                    suitebuf, 6, /* suiteid */
                                    OSSL_HPKE_PSK_HASH_LABEL, /* label */
                                    ctx->psk, ctx->psklen); /* ikmlen */
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    secretlen = hpke_kdf_tab[kdf_ind].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = ossl_hpke_labeled_extract(kctx,
                                    secret, secretlen,
                                    ctx->shared_secret,
                                    ctx->shared_secretlen, /* salt */
                                    OSSL_HPKE_SEC51LABEL, /* protocol label */
                                    suitebuf, 6, /* suiteid */
                                    OSSL_HPKE_SECRET_LABEL, /* label */
                                    ctx->psk, ctx->psklen); /* ikmlen */
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    noncelen = hpke_aead_tab[aead_ind].Nn;
    erv = ossl_hpke_labeled_expand(kctx,
                                   nonce, noncelen,
                                   secret, secretlen, /* salt */
                                   OSSL_HPKE_SEC51LABEL, /* protocol label */
                                   suitebuf, 6, /* suiteid */
                                   OSSL_HPKE_NONCE_LABEL, /* label */
                                   ks_context, ks_contextlen); /* ikmlen */
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    seqlen = hpke_seq2buf(ctx->seq, seqbuf, 12);
    if (seqlen == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    } else {
        size_t sind;
        unsigned char cv;

        if (seqlen > noncelen) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            if (sind < seqlen) {
                cv = seqbuf[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }
    keylen = hpke_aead_tab[aead_ind].Nk;
    erv = ossl_hpke_labeled_expand(kctx,
                                   key, keylen,
                                   secret, secretlen, /* salt */
                                   OSSL_HPKE_SEC51LABEL, /* protocol label */
                                   suitebuf, 6, /* suiteid */
                                   OSSL_HPKE_KEY_LABEL, /* label */
                                   ks_context, ks_contextlen); /* ikmlen */
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ctx->exportersec == NULL) {
        ctx->exporterseclen = hpke_kdf_tab[kdf_ind].Nh;
        ctx->exportersec = OPENSSL_malloc(ctx->exporterseclen);
        if (ctx->exportersec == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        erv = ossl_hpke_labeled_expand(kctx,
                                       ctx->exportersec, ctx->exporterseclen,
                                       secret, secretlen,
                                       OSSL_HPKE_SEC51LABEL,
                                       suitebuf, 6,
                                       OSSL_HPKE_EXP_LABEL,
                                       ks_context, ks_contextlen);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (do_enc == 1) {
        erv = hpke_aead_enc(ctx->libctx, ctx->propq, ctx->suite,
                            key, keylen, nonce, noncelen,
                            aad, aadlen, pt, *ptlen, ct, ctlen);
    } else {
        erv = hpke_aead_dec(ctx->libctx, ctx->propq, ctx->suite,
                            key, keylen, nonce, noncelen,
                            aad, aadlen, ct, *ctlen, pt, ptlen);
    }
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

err:
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
           hpke_mode_strtab[ctx->mode], ctx->mode,
           hpke_kem_strtab[kem_ind], ctx->suite.kem_id,
           hpke_kdf_strtab[kdf_ind], ctx->suite.kdf_id,
           hpke_aead_strtab[aead_ind], ctx->suite.aead_id);
    hpke_pbuf(stdout, "\tpsk_hash", psk_hash, psk_hashlen);
    hpke_pbuf(stdout, "\tks_context", ks_context, ks_contextlen);
    hpke_pbuf(stdout, "\tsecret", secret, secretlen);
    hpke_pbuf(stdout, "\tinfo", info, infolen);
    hpke_pbuf(stdout, "\taad", aad, aadlen);
    hpke_pbuf(stdout, "\tseq", seqbuf, seqlen);
    hpke_pbuf(stdout, "\tnonce", nonce, noncelen);
    hpke_pbuf(stdout, "\tkey", key, keylen);
    hpke_pbuf(stdout, "\texportersec", ctx->exportersec, ctx->exporterseclen);
    hpke_pbuf(stdout, "\tplaintext", pt, *ptlen);
    hpke_pbuf(stdout, "\tciphertext", ct, *ctlen);
    if (ctx->mode == OSSL_HPKE_MODE_PSK
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        fprintf(stdout, "\tpskid: %s\n", ctx->pskid);
        hpke_pbuf(stdout, "\tpsk", ctx->psk, ctx->psklen);
    }
#endif
    EVP_KDF_CTX_free(kctx);
    return erv;
}
#endif /* not HAPPYKEY */

/* externally visible functions from below here */

/**
 * @brief contex creator
 * @param mode is the desired HPKE mode
 * @param suite specifies the KEM, KDF and AEAD to use
 * @param libctx is the context to use
 * @param propq is a properties string
 * @return pointer to new context or NULL if error
 */
OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_HPKE_CTX *ctx = NULL;

    if (hpke_suite_check(suite) != 1)
        return NULL;
    if (mode < 0 || mode > OSSL_HPKE_MODE_PSKAUTH)
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(OSSL_HPKE_CTX));
    if (ctx == NULL)
        return ctx;
    ctx->libctx = libctx;
    if (propq != NULL) {
        ctx->propq = OPENSSL_strdup(propq);
        if (ctx->propq == NULL)
            goto err;
    }
    ctx->mode = mode;
    ctx->suite = suite;
    return ctx;

err:
    OSSL_HPKE_CTX_free(ctx);
    return NULL;
}

/**
 * @brief free up storage for a HPKE context
 * @param ctx is the pointer to be free'd (can be NULL)
 */
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx)
{
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx->propq);
    if (ctx->exportersec)
        OPENSSL_cleanse(ctx->exportersec, ctx->exporterseclen);
    OPENSSL_free(ctx->exportersec);
    OPENSSL_free(ctx->pskid);
    OPENSSL_cleanse(ctx->psk, ctx->psklen);
    OPENSSL_free(ctx->psk);
    OPENSSL_free(ctx->shared_secret);
    OPENSSL_free(ctx->ikme);

    EVP_PKEY_free(ctx->authpriv);
    EVP_PKEY_free(ctx->senderpriv);

    OPENSSL_free(ctx->authpub);

    OPENSSL_free(ctx);
    return;
}

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
                           const unsigned char *psk, size_t psklen)
{
#ifdef HAPPYKEY
    int erv = 1;

#endif
    if (ctx == NULL || pskid == NULL || psk == NULL || psklen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->mode != OSSL_HPKE_MODE_PSK
        && ctx->mode != OSSL_HPKE_MODE_PSKAUTH) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* free previous value if any */
    OPENSSL_free(ctx->pskid);
    OPENSSL_cleanse(ctx->psk, ctx->psklen);
    OPENSSL_free(ctx->psk);
    ctx->pskid = OPENSSL_strdup(pskid);
    if (ctx->pskid == NULL)
        goto err;
    ctx->psk = OPENSSL_malloc(psklen);
    if (ctx->psk == NULL)
        goto err;
    memcpy(ctx->psk, psk, psklen);
    ctx->psklen = psklen;
    return 1;
err:
    /* zap any new or old psk */
    OPENSSL_free(ctx->pskid);
    OPENSSL_cleanse(ctx->psk, ctx->psklen);
    OPENSSL_free(ctx->psk);
    ctx->psklen = 0;
    return 0;
}

/**
 * @brief set a sender private key for HPKE
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_senderpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *privp)
{
#ifdef HAPPYKEY
    int erv = 1;

#endif
    if (ctx == NULL || privp == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->senderpriv != NULL)
        EVP_PKEY_free(ctx->senderpriv);
    ctx->senderpriv = EVP_PKEY_dup(privp);
    if (ctx->senderpriv == NULL)
        return 0;
    return 1;
}

/**
 * @brief set a sender IKM for key DHKEM generation
 * @param ctx is the pointer for the HPKE context
 * @param ikme is a buffer for the IKM
 * @param ikmelen is the length of the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx,
                            const unsigned char *ikme, size_t ikmelen)
{
#ifdef HAPPYKEY
    int erv = 1;

#endif
    if (ctx == NULL || ikme == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    OPENSSL_free(ctx->ikme);
    ctx->ikme = OPENSSL_malloc(ikmelen);
    if (ctx->ikme == NULL)
        return 0;
    memcpy(ctx->ikme, ikme, ikmelen);
    ctx->ikmelen = ikmelen;
    return 1;
}

/**
 * @brief set a private key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *privp)
{
#ifdef HAPPYKEY
    int erv = 1;

#endif
    if (ctx == NULL || privp == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->mode != OSSL_HPKE_MODE_AUTH
        && ctx->mode != OSSL_HPKE_MODE_PSKAUTH) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->authpriv != NULL)
        EVP_PKEY_free(ctx->authpriv);
    ctx->authpriv = EVP_PKEY_dup(privp);
    if (ctx->authpriv == NULL)
        return 0;
    return 1;
}

/**
 * @brief set a public key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param pub is an buffer form of the public key
 * @param publen is the length of the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_authpub(OSSL_HPKE_CTX *ctx,
                               const unsigned char *pub, size_t publen)
{
    if (ctx == NULL)
        return 0;
    if (ctx->authpub != NULL)
        OPENSSL_free(ctx->authpub);
    ctx->authpub = OPENSSL_malloc(publen);
    if (ctx->authpub == NULL)
        return 0;
    memcpy(ctx->authpub, pub, publen);
    ctx->authpublen = publen;
    return 1;
}

/**
 * @brief ask for the state of the sequence of seal/open calls
 * @param ctx is the pointer for the HPKE context
 * @param seq returns the positive integer sequence number
 * @return 1 for success, 0 for error
 *
 * The value returned is the most recent used when sealing
 * or opening (successfully)
 */
int OSSL_HPKE_CTX_get0_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq)
{
    if (ctx == NULL || seq == NULL)
        return 0;
    *seq = ctx->seq;
    return 1;
}

/**
 * @brief set the sequence value for seal/open calls
 * @param ctx is the pointer for the HPKE context
 * @param seq set the positive integer sequence number
 * @return 1 for success, 0 for error
 *
 * The value returned is the most recent used when sealing
 * or opening (successfully)
 */
int OSSL_HPKE_CTX_set1_seq(OSSL_HPKE_CTX *ctx, uint64_t seq)
{
#ifdef HAPPYKEY
    int erv = 1;

#endif
    if (ctx == NULL)
        return 0;
    ctx->seq = seq;
    return 1;
}

/**
 * @brief sender seal function
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @param pub is the recipient public key octets
 * @param publen is the size the above
 * @param infolen is the size the above
 * @param info is the key schedule info parameter
 * @param infolen is the size the above
 * @param info is the info parameter
 * @param infolen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @return 1 for success, 0 for error
 *
 * This can be called multiple times
 */
int OSSL_HPKE_sender_seal(OSSL_HPKE_CTX *ctx,
                          unsigned char *enc, size_t *enclen,
                          unsigned char *ct, size_t *ctlen,
                          unsigned char *pub, size_t publen,
                          const unsigned char *info, size_t infolen,
                          const unsigned char *aad, size_t aadlen,
                          const unsigned char *pt, size_t ptlen)
{
    int erv = 1;
#ifdef HAPPYKEY
    unsigned char seqbuf[12]; /* 12 octets is the max nonce */
    size_t seqlen = 1;
    unsigned char exportersec[OSSL_HPKE_MAXSIZE];
    size_t exporterseclen = OSSL_HPKE_MAXSIZE;
#endif

    if (ctx == NULL || enc == NULL || enclen == NULL || *enclen == 0
        || ct == NULL || ctlen == NULL || *ctlen == 0
        || pub == NULL || publen == 0 || pt == NULL || ptlen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }

#ifndef HAPPYKEY
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("DHKEM Sealing:\n");
#endif
    if (ctx->shared_secret == NULL) {
        erv = hpke_encap(ctx, enc, enclen, pub, publen);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
     else {
        hpke_pbuf(stdout, "\texisting shared secret", ctx->shared_secret,
                  ctx->shared_secretlen);
     }
#endif
    erv = hpke_do_rest(ctx, 1, ct, ctlen, (unsigned char *)pt, &ptlen,
                       info, infolen, aad, aadlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    } else {
        ctx->seq++;
    }
#else
    seqlen = hpke_seq2buf(ctx->seq, seqbuf, sizeof(seqbuf));
    if (seqlen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->senderpriv == NULL) {
        /* generate a key pair for ephemeral, or repeaated, use */
        size_t mypublen = OSSL_HPKE_MAXSIZE;
        unsigned char mypub[OSSL_HPKE_MAXSIZE];

        if (OSSL_HPKE_keygen(ctx->libctx, ctx->propq, ctx->mode, ctx->suite,
                             NULL, 0, mypub, &mypublen,
                             &ctx->senderpriv) != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    erv = hpke_enc_int(ctx->libctx, ctx->propq, ctx->mode, ctx->suite,
                       ctx->pskid, ctx->psklen, ctx->psk,
                       publen, pub,
                       0, NULL, ctx->authpriv,
                       ptlen, pt,
                       aadlen, aad,
                       infolen, info,
                       seqlen, seqbuf,
                       ctx->senderpriv,
                       0, NULL,
                       &exporterseclen, exportersec,
                       enclen, enc,
                       ctlen, ct
#ifdef TESTVECTORS
                       , NULL
#endif
                        );
    if (erv == 1) {
        ctx->seq++;
        if (ctx->seq == 0) { /* error wrap around 64 bits */
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (ctx->exportersec == NULL) {
            /* just record once */
            ctx->exportersec = OPENSSL_malloc(exporterseclen);
            if (ctx->exportersec == NULL) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            memcpy(ctx->exportersec, exportersec, exporterseclen);
            ctx->exporterseclen = exporterseclen;
        }
    }
#endif
    return erv;
}

/**
 * @brief recipient open function
 * @param ctx is the pointer for the HPKE context
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param recippriv is the EVP_PKEY form of recipient private value
 * @param info is the info parameter
 * @param infolen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @return 1 for success, 0 for error
 *
 * This can be called multiple times.
 */
int OSSL_HPKE_recipient_open(OSSL_HPKE_CTX *ctx,
                             unsigned char *pt, size_t *ptlen,
                             const unsigned char *enc, size_t enclen,
                             EVP_PKEY *recippriv,
                             const unsigned char *info, size_t infolen,
                             const unsigned char *aad, size_t aadlen,
                             const unsigned char *ct, size_t ctlen)
{
    int erv = 1;
#ifdef HAPPYKEY
    unsigned char seqbuf[12];
    size_t seqlen = 1;
    unsigned char exportersec[OSSL_HPKE_MAXSIZE];
    size_t exporterseclen = OSSL_HPKE_MAXSIZE;
#endif

    if (ctx == NULL || pt == NULL || ptlen == NULL || *ptlen == 0
        || enc == NULL || enclen == 0 || ct == NULL || ctlen == 0
        || recippriv == NULL || ct == NULL || ctlen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#ifndef HAPPYKEY
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("DHKEM Opening:\n");
#endif
    if (ctx->shared_secret == NULL) {
        erv = hpke_decap(ctx, enc, enclen, recippriv);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
     else {
        hpke_pbuf(stdout, "\texisting shared secret", ctx->shared_secret,
                  ctx->shared_secretlen);
     }
#endif
    erv = hpke_do_rest(ctx, 0, (unsigned char *)ct, &ctlen, pt, ptlen,
                       info, infolen, aad, aadlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    } else {
        ctx->seq++;
    }
#else
    seqlen = hpke_seq2buf(ctx->seq, seqbuf, 12);
    if (seqlen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    erv = hpke_dec_int(ctx->libctx, ctx->propq, ctx->mode, ctx->suite,
                       ctx->pskid, ctx->psklen, ctx->psk,
                       ctx->authpublen, ctx->authpub,
                       0, NULL, recippriv,
                       enclen, enc,
                       ctlen, ct,
                       aadlen, aad,
                       infolen, info,
                       seqlen, seqbuf,
                       &exporterseclen, exportersec,
                       ptlen, pt);
    if (erv == 1) {
        if (ctx->exportersec == NULL) {
            /* just record once */
            ctx->exportersec = OPENSSL_malloc(exporterseclen);
            if (ctx->exportersec == NULL) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            memcpy(ctx->exportersec, exportersec, exporterseclen);
            ctx->exporterseclen = exporterseclen;
        }
        ctx->seq++;
        if (ctx->seq == 0) { /* error wrap around 64 bits */
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#endif
    return erv;
}

/**
 * @brief generate a given-length secret based on context and label
 * @param ctx is the HPKE context
 * @param secret is the resulting secret that will be of length...
 * @param secret_len is the desired output length
 * @param label is a buffer to provide separation between secrets
 * @param labellen is the length of the above
 * @return 1 for good, 0 for error
 *
 * The context has to have been used already for one encryption
 * or decryption for this to work (as this is based on the negotiated
 * "exporter_secret" estabilshed via the HPKE operation.
 */
int OSSL_HPKE_CTX_export(OSSL_HPKE_CTX *ctx,
                         unsigned char *secret,
                         size_t secret_len,
                         const unsigned char *label,
                         size_t labellen)
{
    int erv = 1;
#ifdef HAPPYKEY
    size_t lsecretlen = secret_len;
#else
    EVP_KDF_CTX *kctx = NULL;
    unsigned char suitebuf[6];
    const char *mdname = NULL;
    int kdf_ind = 0;
#endif

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->exportersec == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#ifndef HAPPYKEY
    kdf_ind = kdf_iana2index(ctx->suite.kdf_id);
    if (kdf_ind == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    mdname = hpke_kdf_tab[kdf_ind].mdname;
    kctx = ossl_kdf_ctx_create("HKDF", mdname, ctx->libctx, ctx->propq);
    if (kctx == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* mode == FULL as per RFC9180 sec 5.1 */
    suitebuf[0] = ctx->suite.kem_id / 256;
    suitebuf[1] = ctx->suite.kem_id % 256;
    suitebuf[2] = ctx->suite.kdf_id / 256;
    suitebuf[3] = ctx->suite.kdf_id % 256;
    suitebuf[4] = ctx->suite.aead_id / 256;
    suitebuf[5] = ctx->suite.aead_id % 256;
    erv = ossl_hpke_labeled_expand(kctx,
                                   secret, secret_len,
                                   ctx->exportersec, ctx->exporterseclen,
                                   OSSL_HPKE_SEC51LABEL,
                                   suitebuf, 6,
                                   OSSL_HPKE_EXP_SEC_LABEL,
                                   label, labellen);
    EVP_KDF_CTX_free(kctx);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#else
    erv = hpke_expand(ctx->libctx, ctx->propq, ctx->suite,
                      OSSL_HPKE_5869_MODE_FULL,
                      ctx->exportersec, ctx->exporterseclen,
                      OSSL_HPKE_EXP_SEC_LABEL, strlen(OSSL_HPKE_EXP_SEC_LABEL),
                      label, labellen,
                      secret_len, secret, &lsecretlen);
    if (erv != 1 || secret_len != lsecretlen) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
#endif
#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("Exporting (%lu)\n", secret_len);
    hpke_pbuf(stdout, "\tctx->exportersec", ctx->exportersec,
              ctx->exporterseclen);
    hpke_pbuf(stdout, "\tlabel/context", label, labellen);
    hpke_pbuf(stdout, "\texported secret", secret, secret_len);
#endif
    return 1;
}

#ifdef HAPPYKEY
/*
 * @brief generate a key pair
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikmlen is the length of IKM, if supplied
 * @param ikm is IKM, if supplied
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_keygen_buf(OSSL_LIB_CTX *libctx, const char *propq,
                         unsigned int mode, OSSL_HPKE_SUITE suite,
                         const unsigned char *ikm, size_t ikmlen,
                         unsigned char *pub, size_t *publen,
                         unsigned char *priv, size_t *privlen)
{
    return hpke_kg(libctx, propq, mode, suite, ikmlen, ikm,
                   publen, pub, privlen, priv);
}
#endif

/*
 * @brief generate a key pair but keep private inside API
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikmlen is the length of IKM, if supplied
 * @param ikm is IKM, if supplied
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                     unsigned int mode, OSSL_HPKE_SUITE suite,
                     const unsigned char *ikm, size_t ikmlen,
                     unsigned char *pub, size_t *publen,
                     EVP_PKEY **priv)
{
    return hpke_kg_evp(libctx, propq, mode, suite,
                       ikmlen, ikm, publen, pub, priv);
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not-1 otherwise
 */
int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite)
{
    return hpke_suite_check(suite);
}

#ifdef HAPPYKEY
/*
 * @brief: map a kem_id and a private key buffer into an EVP_PKEY
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
int OSSL_HPKE_prbuf2evp(OSSL_LIB_CTX *libctx, const char *propq,
                        unsigned int kem_id,
                        const unsigned char *prbuf, size_t prbuf_len,
                        const unsigned char *pubuf, size_t pubuf_len,
                        EVP_PKEY **priv)
{
    return hpke_prbuf2evp(libctx, propq, kem_id, prbuf, prbuf_len, pubuf,
                          pubuf_len, priv);
}
#endif
/*
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 *
 * As usual buffers are caller allocated and lengths on input are buffer size.
 *
 * @param libctx is the context to use
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
                          size_t cipher_len)
{
    return hpke_good4grease(libctx, propq, suite_in, suite,
                            pub, pub_len, cipher, cipher_len);
}

/*
 * @brief map a string to a HPKE suite
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite)
{
    return hpke_str2suite(str, suite);
}

/*
 * @brief tell the caller how big the cipertext will be
 * @param suite is the suite to be used
 * @param enclen points to what'll be enc length
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 */
int OSSL_HPKE_expansion(OSSL_HPKE_SUITE suite,
                        size_t *enclen,
                        size_t clearlen,
                        size_t *cipherlen)
{
    return hpke_expansion(suite, enclen, clearlen, cipherlen);
}

/* the "legacy" enc/dec API functions below here. will likely disappear */

/*
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output.
 *
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
 * @param senderpriv is the sender's private key (if being re-used)
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
#ifdef TESTVECTORS
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
                  void *tv)
#else
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
                  unsigned char *cipher, size_t *cipherlen)
#endif
{
#ifdef TESTVECTORS
    if (senderpublen == NULL)
        return 0;
    return hpke_enc_int(libctx, propq, mode, suite,
                        pskid, psklen, psk,
                        publen, pub,
                        authprivlen, authpriv, authpriv_evp,
                        clearlen, clear,
                        aadlen, aad,
                        infolen, info,
                        seqlen, seq,
                        senderpriv,
                        0, NULL, /* raw sender priv */
                        NULL, NULL, /* exporter */
                        senderpublen, senderpub,
                        cipherlen, cipher, tv);

#else
#ifndef HAPPYKEY
    int erv = 1;
    OSSL_HPKE_CTX *ctx = NULL;

#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("DHKEM Encrypting:\n");
#endif
    ctx = OSSL_HPKE_CTX_new(mode, suite, libctx, propq);
    if (!ctx) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (seq != NULL) {
        /* need to map to uint64_t and use setter */
        uint64_t sval = 0;
        size_t i;

        if (seqlen > 8) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        for (i = 0; i != seqlen; i++)
            sval = sval * 256 + seq[i];
        erv = OSSL_HPKE_CTX_set1_seq(ctx, sval);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (ctx->mode == OSSL_HPKE_MODE_AUTH
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (authpriv_evp != NULL) {
            erv = OSSL_HPKE_CTX_set1_authpriv(ctx, authpriv_evp);
            if (erv != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            EVP_PKEY *tpriv = NULL;

            erv = hpke_prbuf2evp(libctx, propq, suite.kem_id,
                                 authpriv, authprivlen,
                                 NULL, 0, &tpriv);
            if (erv != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            erv = OSSL_HPKE_CTX_set1_authpriv(ctx, tpriv);
            if (erv != 1) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            EVP_PKEY_free(tpriv);
        }
    }
    if (ctx->mode == OSSL_HPKE_MODE_PSK
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        erv = OSSL_HPKE_CTX_set1_psk(ctx, pskid, psk, psklen);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    erv = hpke_encap(ctx, senderpub, senderpublen, pub, publen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = hpke_do_rest(ctx, 1, cipher, cipherlen,
                       (unsigned char *)clear, &clearlen,
                       info, infolen, aad, aadlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
err:
    OSSL_HPKE_CTX_free(ctx);
    return erv;
#else
    if (senderpublen == NULL)
        return 0;
    return hpke_enc_int(libctx, propq, mode, suite,
                        pskid, psklen, psk,
                        publen, pub,
                        authprivlen, authpriv, authpriv_evp,
                        clearlen, clear,
                        aadlen, aad,
                        infolen, info,
                        seqlen, seq,
                        senderpriv,
                        0, NULL, /* raw sender priv */
                        NULL, NULL, /* exporter sec */
                        senderpublen, senderpub,
                        cipherlen, cipher);
#endif
#endif
}

#ifdef HAPPYKEY
/*
 * @brief HPKE encryption function, with externally supplied sender key pair
 *
 * This function is provided with an ECDH key pair that is used for
 * HPKE encryption.
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
#ifdef TESTVECTORS
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
                      unsigned char *cipher, size_t *cipherlen, void *tv)
#else
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
                      unsigned char *cipher, size_t *cipherlen)
#endif
{
#ifdef TESTVECTORS
    return hpke_enc_int(libctx, propq, mode, suite,
                        pskid, psklen, psk,
                        publen, pub,
                        authprivlen, authpriv, authpriv_evp,
                        clearlen, clear,
                        aadlen, aad,
                        infolen, info,
                        seqlen, seq,
                        senderpriv,
                        0, NULL,
                        NULL, NULL, /* exporter sec */
                        0, NULL,
                        cipherlen, cipher, tv);
#else
    return hpke_enc_int(libctx, propq, mode, suite,
                        pskid, psklen, psk,
                        publen, pub,
                        authprivlen, authpriv, authpriv_evp,
                        clearlen, clear,
                        aadlen, aad,
                        infolen, info,
                        seqlen, seq,
                        senderpriv,
                        0, NULL,
                        NULL, NULL, /* exporter sec */
                        0, NULL,
                        cipherlen, cipher);
#endif
}
#endif
/*
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use
 * @param propq is a properties string
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
                  unsigned char *clear, size_t *clearlen)
{
#ifndef HAPPYKEY
    int erv = 1;
    OSSL_HPKE_CTX *ctx = NULL;

#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
    printf("DHKEM Decrypting:\n");
#endif
    ctx = OSSL_HPKE_CTX_new(mode, suite, libctx, propq);
    if (!ctx) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (seq != NULL) {
        /* need to map to uint64_t and use setter */
        uint64_t sval = 0;
        size_t i;

        if (seqlen > 8) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        for (i = 0; i != seqlen; i++)
            sval = sval * 256 + seq[i];
        erv = OSSL_HPKE_CTX_set1_seq(ctx, sval);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (ctx->mode == OSSL_HPKE_MODE_AUTH
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        erv = OSSL_HPKE_CTX_set1_authpub(ctx, pub, publen);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (ctx->mode == OSSL_HPKE_MODE_PSK
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        erv = OSSL_HPKE_CTX_set1_psk(ctx, pskid, psk, psklen);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (evppriv != NULL) {
        erv = hpke_decap(ctx, enc, enclen, evppriv);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        EVP_PKEY *tpriv = NULL;

        erv = hpke_prbuf2evp(libctx, propq, suite.kem_id,
                             priv, privlen,
                             NULL, 0, &tpriv);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        erv = hpke_decap(ctx, enc, enclen, tpriv);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        EVP_PKEY_free(tpriv);
    }
    erv = hpke_do_rest(ctx, 0, (unsigned char *)cipher, &cipherlen,
                       clear, clearlen,
                       info, infolen, aad, aadlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
err:
    OSSL_HPKE_CTX_free(ctx);
    return erv;
#else
    return hpke_dec_int(libctx, propq, mode, suite,
                        pskid, psklen, psk,
                        publen, pub,
                        privlen, priv, evppriv,
                        enclen, enc,
                        cipherlen, cipher,
                        aadlen, aad,
                        infolen, info,
                        seqlen, seq,
                        NULL, NULL, /* exporter */
                        clearlen, clear);
#endif
}
