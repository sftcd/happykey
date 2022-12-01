/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* An OpenSSL-based HPKE implementation of RFC9180 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <internal/packet.h>
#include <internal/common.h>
/*
 * If we're building standalone (from github.com/sftcd/happykey) then
 * include the local headers.
 */
#include "hpke.h"
#include "hpke_util.h"
#include "hpke_oldapi.h"
/*
 * Define this for LOADS of printing of intermediate cryptographic values
 * Really only needed when new crypto added (hopefully)
 */
#define SUPERVERBOSE

/** default buffer size for keys and internal buffers we use */
#define OSSL_HPKE_MAXSIZE 512

/* Define HPKE labels from RFC9180 in hex for EBCDIC compatibility */
/* "HPKE" - "suite_id" label for section 5.1 */
static const char OSSL_HPKE_SEC51LABEL[] = "\x48\x50\x4b\x45";
/* "psk_id_hash" - in key_schedule_context */
static const char OSSL_HPKE_PSKIDHASH_LABEL[] = "\x70\x73\x6b\x5f\x69\x64\x5f\x68\x61\x73\x68";
/*  "info_hash" - in key_schedule_context */
static const char OSSL_HPKE_INFOHASH_LABEL[] = "\x69\x6e\x66\x6f\x5f\x68\x61\x73\x68";
/*  "base_nonce" - base nonce calc label */
static const char OSSL_HPKE_NONCE_LABEL[] = "\x62\x61\x73\x65\x5f\x6e\x6f\x6e\x63\x65";
/*  "exp" - internal exporter secret generation label */
static const char OSSL_HPKE_EXP_LABEL[] = "\x65\x78\x70";
/*  "sec" - external label for exporting secret */
static const char OSSL_HPKE_EXP_SEC_LABEL[] = "\x73\x65\x63";
/*  "key" - label for use when generating key from shared secret */
static const char OSSL_HPKE_KEY_LABEL[] = "\x6b\x65\x79";
/*  "psk_hash" - for hashing PSK */
static const char OSSL_HPKE_PSK_HASH_LABEL[] = "\x70\x73\x6b\x5f\x68\x61\x73\x68";
/*  "secret" - for generating shared secret */
static const char OSSL_HPKE_SECRET_LABEL[] = "\x73\x65\x63\x72\x65\x74";
#ifdef HAPPYKEY
/* an error macro just to make things easier */
# define ERR_raise(__a__, __b__) \
    { \
        if (erv == 1) { erv = 0; } \
    }
#endif
#if defined(SUPERVERBOSE)
static unsigned char *pbuf; /* global var for debug printing */
static size_t pblen = 1024; /* global var for debug printing */

/*
 * @brief for odd/occasional debugging
 * @param fout is a FILE * to use
 * @param msg is prepended to print
 * @param buf is the buffer to print
 * @param blen is the length of the buffer
 * @return 1 for success, 0 otherwise
 */
int hpke_pbuf(FILE *fout, const char *msg,
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
        fprintf(fout, "buf is NULL, so maybe something wrong (or not:-)\n");
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

/**
 * @brief string for KEMs
 */
const char *kem_info_str(const OSSL_HPKE_KEM_INFO *kem_info)
{
    if (kem_info == NULL)
        return "null";
    if (kem_info->groupname != NULL)
        return kem_info->groupname;
    else
        return kem_info->keytype;
}

/**
 * @brief string for KDFs
 */
const char *kdf_info_str(const OSSL_HPKE_KDF_INFO *kdf_info)
{
    if (kdf_info == NULL)
        return "null";
    return kdf_info->mdname;
}

/**
 * @brief string for AEADs
 */
const char *aead_info_str(const OSSL_HPKE_AEAD_INFO *aead_info)
{
    if (aead_info == NULL)
        return "null";
    return aead_info->name;
}

/*
 * @brief table of mode strings
 */
const char *hpke_mode_strtab[4] = {
    OSSL_HPKE_MODESTR_BASE,
    OSSL_HPKE_MODESTR_PSK,
    OSSL_HPKE_MODESTR_AUTH,
    OSSL_HPKE_MODESTR_PSKAUTH};
#endif

/*
 * @brief  Map ascii to binary - utility macro used in >1 place
 */
# define HPKE_A2B(_c_) (_c_ >= '0' && _c_ <= '9' ? (_c_ - '0') :\
                        (_c_ >= 'A' && _c_ <= 'F' ? (_c_ - 'A' + 10) :\
                         (_c_ >= 'a' && _c_ <= 'f' ? (_c_ - 'a' + 10) : 0)))
/**
 * @brief check if KEM uses NIST curve or not
 * @param kem_id is the externally supplied kem_id
 * @return 1 for NIST curves, 0 for other
 */
static int hpke_kem_id_nist_curve(uint16_t kem_id)
{
    const OSSL_HPKE_KEM_INFO *kem_info;

    kem_info = ossl_HPKE_KEM_INFO_find_id(kem_id);
    return kem_info != NULL && kem_info->groupname != NULL;
}

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

/**
 * @brief check mode is in-range and supported
 * @param mode is the caller's chosen mode
 * @return 1 for good mode, 0 otherwise
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
 * @return 1 for success, 0 otherwise
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

/**
 * @brief wrapper to import NIST curve public key as easily as x25519/x448
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param gname is the curve groupname
 * @param buf is the binary buffer with the (uncompressed) public value
 * @param buflen is the length of the private key buffer
 * @return a working EVP_PKEY * or NULL
 *
 * Note that this could be a useful function to make public in
 * future, but would likely require a name change.
 */
static EVP_PKEY *evp_pkey_new_raw_nist_public_key(OSSL_LIB_CTX *libctx,
                                                  const char *propq,
                                                  const char *gname,
                                                  const unsigned char *buf,
                                                  size_t buflen)
{
#ifdef HAPPYKEY
    /*
     * s3_lib.c:ssl_generate_param_group has similar code so
     * can be useful if the upstream code changes
     */
    int erv = 0;
#endif
    OSSL_PARAM params[2];
    EVP_PKEY *ret = NULL;
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)gname, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (cctx == NULL
        || EVP_PKEY_paramgen_init(cctx) <= 0
        || EVP_PKEY_CTX_set_params(cctx, params) <= 0
        || EVP_PKEY_paramgen(cctx, &ret) <= 0
        || EVP_PKEY_set1_encoded_public_key(ret, buf, buflen) != 1) {
#if defined(SUPERVERBOSE)
        printf("EARLY public fail\n");
#endif
        EVP_PKEY_CTX_free(cctx);
        EVP_PKEY_free(ret);
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
#if defined(SUPERVERBOSE)
    if (ret != NULL) {
        pblen = EVP_PKEY_get1_encoded_public_key(ret, &pbuf);
        hpke_pbuf(stdout, "\tEARLY public", pbuf, pblen);
        OPENSSL_free(pbuf);
    } else {
        printf("no EARLY public\n");
    }
#endif
    EVP_PKEY_CTX_free(cctx);
    return ret;
}

/**
 * @brief check if a suite is supported locally
 * @param suite is the suite to check
 * @return 1 for good, 0 otherwise
 */
static int hpke_suite_check(OSSL_HPKE_SUITE suite)
{
    /* check KEM, KDF and AEAD are supported here */
    if (ossl_HPKE_KEM_INFO_find_id(suite.kem_id) == NULL)
        return 0;
    if (ossl_HPKE_KDF_INFO_find_id(suite.kdf_id) == NULL)
        return 0;
    if (ossl_HPKE_AEAD_INFO_find_id(suite.aead_id) == NULL)
        return 0;
    return 1;
}
/*
 * PEM header/footer for private keys
 * PEM_STRING_PKCS8INF is just: "PRIVATE KEY"
 */
#define PEM_PRIVATEHEADER "-----BEGIN "PEM_STRING_PKCS8INF"-----\n"
#define PEM_PRIVATEFOOTER "\n-----END "PEM_STRING_PKCS8INF"-----\n"

/*
 * @brief map a kem_id and a private key buffer into an EVP_PKEY
 *
 * Note that the buffer is expected to be some form of the encoded
 * private key, and could still have the PEM header or not, and might
 * or might not be base64 encoded. We will try handle all those options.
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
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
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
    kem_info = ossl_HPKE_KEM_INFO_find_id(kem_id);
    if (kem_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    keytype = kem_info->keytype;
    groupname = kem_info->groupname;
#if defined(SUPERVERBOSE)
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
    if (kem_info->Nsk == prbuf_len) {
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
            /*
             * this code isn't quite right, but will go away once
             * HPKE PR is merged
             */
            if (!OPENSSL_strcasecmp(groupname,OSSL_HPKE_KEMSTR_P256))
                groupnid = NID_X9_62_prime256v1;
            if (!OPENSSL_strcasecmp(groupname,OSSL_HPKE_KEMSTR_P384))
                groupnid = NID_secp384r1;
            if (!OPENSSL_strcasecmp(groupname,OSSL_HPKE_KEMSTR_P521))
                groupnid = NID_secp521r1;
            if (groupnid == 0) {
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            pubsize = kem_info->Npk;
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
#if defined(SUPERVERBOSE)
    if (erv == 1) {
        printf("\thpke_prbuf2evp success\n");
    } else {
        printf("\thpke_prbuf2evp FAILED with return %d\n", erv);
    }
#endif
#ifndef OPENSSL_NO_EC
    BN_free(calc_priv);
    EC_POINT_free(calc_pub);
    EC_GROUP_free(curve);
    OPENSSL_cleanse(calc_pubuf, OSSL_HPKE_MAXSIZE);
#endif
    OPENSSL_cleanse(hf_prbuf, OSSL_HPKE_MAXSIZE);
    BN_free(priv);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
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


/* Define more HPKE labels from RFC9180 in hex for EBCDIC compatibility */
/* "HPKE-v1" -  version string label */
static const char OSSL_HPKE_VERLABEL[] = "\x48\x50\x4B\x45\x2D\x76\x31";
/* "eae_prk" - label in ExtractAndExpand */
static const char OSSL_HPKE_EAE_PRK_LABEL[] = "\x65\x61\x65\x5f\x70\x72\x6b";
/*  "shared_secret" - shared secret calc label */
static const char OSSL_HPKE_SS_LABEL[] = "\x73\x68\x61\x72\x65\x64\x5f\x73\x65\x63\x72\x65\x74";
/* "KEM" - "suite_id" label for 4.1 */
static const char OSSL_HPKE_SEC41LABEL[] = "\x4b\x45\x4d";
/* "dkp_prk" - DeriveKeyPair label */
static const char OSSL_HPKE_DPK_LABEL[] = "\x64\x6b\x70\x5f\x70\x72\x6b";
/* "candidate" - used in deterministic key gen */
static const char OSSL_HPKE_CAND_LABEL[] = "\x63\x61\x6e\x64\x69\x64\x61\x74\x65";
/* "sk" - label used in deterministic key gen */
static const char OSSL_HPKE_SK_LABEL[] = "\x73\x6b";

/* polyfill for the DHKEM stuff being in the OpenSSL library */
#define OSSL_HPKE_5869_MODE_PURE   0 /* Do "pure" RFC5869 */
#define OSSL_HPKE_5869_MODE_KEM    1 /* Abide by HPKE section 4.1 */
#define OSSL_HPKE_5869_MODE_FULL   2 /* Abide by HPKE section 5.1 */
/*

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
 * @return 1 for success, 0 otherwise
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
    WPACKET pkt;
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
    const OSSL_HPKE_KDF_INFO *kdf_info = NULL;

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
        kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
        if (kem_info == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = kem_info->mdname;
    } else {
        kdf_info = ossl_HPKE_KDF_INFO_find_id(suite.kdf_id);
        if (kdf_info == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = kdf_info->mdname;
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
    OPENSSL_cleanse(labeled_ikmbuf, 2 * OSSL_HPKE_MAXSIZE);
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
 * @return 1 for success, 0 otherwise
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
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
    const OSSL_HPKE_KDF_INFO *kdf_info = NULL;
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
        kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
        if (kem_info == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = kem_info->mdname;
    } else {
        kdf_info = ossl_HPKE_KDF_INFO_find_id(suite.kdf_id);
        if (kdf_info == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        mdname = kdf_info->mdname;
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
    OPENSSL_cleanse(libuf, 2 * OSSL_HPKE_MAXSIZE);
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
 * @return 1 for success, 0 otherwise
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
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;

    kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
    if (kem_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    lsecretlen = kem_info->Nsecret;
#if defined(SUPERVERBOSE)
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
#if defined(SUPERVERBOSE)
    hpke_pbuf(stdout, "\teae_prk", eae_prkbuf, eae_prklen);
#endif
    erv = hpke_expand(libctx, propq, suite, mode5869,
                      eae_prkbuf, eae_prklen,
                      OSSL_HPKE_SS_LABEL, strlen(OSSL_HPKE_SS_LABEL),
                      context, contextlen,
                      lsecretlen, secret, &lsecretlen);
    if (erv != 1) { goto err; }
    *secretlen = lsecretlen;
#if defined(SUPERVERBOSE)
    hpke_pbuf(stdout, "\tshared secret", secret, *secretlen);
#endif
err:
    OPENSSL_cleanse(eae_prkbuf, OSSL_HPKE_MAXSIZE);
    memset(eae_prkbuf, 0, sizeof(eae_prkbuf));
    return erv;
}

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
 * @return 1 for success, 0 otherwise
 */
int hpke_do_kem(OSSL_LIB_CTX *libctx, const char *propq,
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

    /* run DH KEM to get zz */
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
#if defined(SUPERVERBOSE)
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
    OPENSSL_cleanse(zz, 2 * OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(kem_context, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(lss, OSSL_HPKE_MAXSIZE);
    EVP_PKEY_CTX_free(pctx);
    return erv;
}

/*
 * @brief generate a key pair
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
int local_hpke_kg_evp(OSSL_LIB_CTX *libctx, const char *propq,
                             OSSL_HPKE_SUITE suite,
                             size_t ikmlen, const unsigned char *ikm,
                             size_t *publen, unsigned char *pub,
                             EVP_PKEY **priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    int cmp = 0;
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;

    if (hpke_suite_check(suite) != 1)
        return 0;
    if (pub == NULL || publen == NULL || *publen == 0 || priv == NULL)
        return 0;
    if (ikmlen > 0 && ikm == NULL)
        return 0;
    if (ikmlen == 0 && ikm != NULL)
        return 0;
    if (ikmlen > OSSL_HPKE_MAX_PARMLEN)
        return 0;
    kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
    if (kem_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* setup generation of key pair */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        /* TODO: check this use of propq!!! */
        pctx = EVP_PKEY_CTX_new_from_name(libctx, kem_info->keytype,
                                          (propq != NULL ? propq
                                           : kem_info->groupname)
                                          );
        if (pctx == NULL
            || EVP_PKEY_paramgen_init(pctx) != 1
            || EVP_PKEY_keygen_init(pctx) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set_group_name(pctx, kem_info->groupname) != 1) {
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
                                  &counter, 1, kem_info->Nsk,
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
            OPENSSL_cleanse(sk, sklen);
            OPENSSL_cleanse(tmp, sizeof(tmp));
            if (erv != 1) { goto err; }
        }
#ifdef SUPERVERBOSE
        else {
            printf("Random KG for KEM %d\n", suite.kem_id);
        }
#endif
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, kem_info->keytype, propq);
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
                              NULL, 0, kem_info->Nsk, sk, &sklen);
            if (erv != 1) {
                memset(tmp, 0, sizeof(tmp));
                goto err;
            }
#ifdef SUPERVERBOSE
            hpke_pbuf(stdout, "\tdeterministic sk", sk, sklen);
#endif
            erv = hpke_prbuf2evp(libctx, propq, suite.kem_id, sk, sklen,
                                 NULL, 0, &skR);
            OPENSSL_cleanse(sk, sklen);
            OPENSSL_cleanse(tmp, sizeof(tmp));
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
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    if (EVP_PKEY_get_octet_string_param(skR, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pub, *publen, publen) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef SUPERVERBOSE
    hpke_pbuf(stdout, "\tkg_evp pub", pub, *publen);
#endif
    *priv = skR;

err:
    if (erv != 1) { EVP_PKEY_free(skR); }
    EVP_PKEY_CTX_free(pctx);
    return erv;
}

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
    erv = local_hpke_kg_evp(libctx, propq, suite, ikmlen, ikm,
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
    OPENSSL_cleanse(lpriv, OSSL_HPKE_MAXSIZE);
    EVP_PKEY_free(skR);
    BIO_free_all(bfp);
    return erv;
}

/**
 * @brief do the AEAD decryption
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param ct is the ciphertext buffer
 * @param ctlen is the ciphertext length (including tag).
 * @param pt is the output buffer
 * @param ptlen input/output, better be big enough on input, exact on output
 * @return 1 on success, 0 otherwise
 */
static int hpke_aead_dec(OSSL_LIB_CTX *libctx, const char *propq,
                         OSSL_HPKE_SUITE suite,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *ct, size_t ctlen,
                         unsigned char *pt, size_t *ptlen)
{
    int erv = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    size_t taglen;
    EVP_CIPHER *enc = NULL;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;

    if (pt == NULL || ptlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aead_info = ossl_HPKE_AEAD_INFO_find_id(suite.aead_id);
    if (aead_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    taglen = aead_info->taglen;
    if (ctlen <= taglen || *ptlen < ctlen - taglen) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise the encryption operation */
    enc = EVP_CIPHER_fetch(libctx, aead_info->name, propq);
    if (enc == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide AAD. */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen - taglen) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *ptlen = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                             taglen, (void *)(ct + ctlen - taglen))) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Finalise decryption.  */
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) <= 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = 1;

err:
    if (erv != 1)
        OPENSSL_cleanse(pt, *ptlen);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    return erv;
}

/**
 * @brief do AEAD encryption as per the RFC
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param pt is the plaintext buffer
 * @param ptlen is the length of pt
 * @param ct is the output buffer
 * @param ctlen input/output, needs space for tag on input, exact on output
 * @return 1 for success, 0 otherwise
 */
static int hpke_aead_enc(OSSL_LIB_CTX *libctx, const char *propq,
                         OSSL_HPKE_SUITE suite,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *pt, size_t ptlen,
                         unsigned char *ct, size_t *ctlen)
{
    int erv = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    size_t taglen = 0;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;
    EVP_CIPHER *enc = NULL;
    unsigned char tag[16];

    if (ct == NULL || ctlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aead_info = ossl_HPKE_AEAD_INFO_find_id(suite.aead_id);
    if (aead_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    taglen = aead_info->taglen;
    if (*ctlen <= taglen || ptlen > *ctlen - taglen) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        goto err;
    }
    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise the encryption operation. */
    enc = EVP_CIPHER_fetch(libctx, aead_info->name, propq);
    if (enc == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide any AAD data. */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *ctlen = len;
    /* Finalise the encryption. */
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *ctlen += len;
    /* Get tag. Not a duplicate so needs to be added to the ciphertext */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(ct + *ctlen, tag, taglen);
    *ctlen += taglen;
    erv = 1;

err:
    if (erv != 1)
        OPENSSL_cleanse(ct, *ctlen);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    return erv;
}

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
{
    int erv = 1; /* Our error return value - 1 is success */
    int evpcaller = 0;
    int rawcaller = 0;
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
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
    const OSSL_HPKE_KDF_INFO *kdf_info = NULL;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;

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
#if defined(SUPERVERBOSE)
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
    kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
    if (kem_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkR = evp_pkey_new_raw_nist_public_key(libctx, propq,
                                               kem_info->groupname,
                                               pub, publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key_ex(libctx,
                                             kem_info->keytype,
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
        if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
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
#if defined(SUPERVERBOSE)
    hpke_pbuf(stdout, "\tpsk_hash", psk_hash, psk_hashlen);
#endif
    kdf_info = ossl_HPKE_KDF_INFO_find_id(suite.kdf_id);
    if (kdf_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    secretlen = kdf_info->Nh;
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
    aead_info = ossl_HPKE_AEAD_INFO_find_id(suite.aead_id);
    if (aead_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    noncelen = aead_info->Nn;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_NONCE_LABEL, strlen(OSSL_HPKE_NONCE_LABEL),
                      ks_context, ks_contextlen, noncelen, nonce, &noncelen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (noncelen != aead_info->Nn) {
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
    keylen = aead_info->Nk;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_KEY_LABEL, strlen(OSSL_HPKE_KEY_LABEL),
                      ks_context, ks_contextlen, keylen, key, &keylen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    exporterseclen = kdf_info->Nh;
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
#if defined(SUPERVERBOSE)
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d) (erv=%d)\n",
           hpke_mode_strtab[mode], mode,
           kem_info_str(kem_info), suite.kem_id,
           kdf_info_str(kdf_info), suite.kdf_id,
           aead_info_str(aead_info), suite.aead_id,
           erv);
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
    OPENSSL_cleanse(ks_context, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(secret, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(psk_hash, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(nonce, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(key, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(exportersec, OSSL_HPKE_MAXSIZE);
    OPENSSL_free(mypub);
    BIO_free_all(bfp);
    EVP_PKEY_free(pkR);
    if (!evpcaller) { EVP_PKEY_free(pkE); }
    if (authpriv_evp == NULL)
        EVP_PKEY_free(skI);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_clear_free(shared_secret, shared_secretlen);
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
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
    const OSSL_HPKE_KDF_INFO *kdf_info = NULL;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;

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
    kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
    if (kem_info == NULL) {
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
#if defined(SUPERVERBOSE)
    printf("Decrypting:\n");
#endif
    /* step 0. Initialise peer's key(s) from string(s) */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkE = evp_pkey_new_raw_nist_public_key(libctx, propq,
                                               kem_info->groupname,
                                               enc, enclen);
    } else {
        pkE = EVP_PKEY_new_raw_public_key_ex(libctx,
                                             kem_info->keytype,
                                             propq, enc, enclen);
    }
    if (pkE == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (authpublen != 0 && authpub != NULL) {
        if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
            pkI = evp_pkey_new_raw_nist_public_key(libctx, propq,
                                                   kem_info->groupname,
                                                   authpub, authpublen);
        } else {
            pkI = EVP_PKEY_new_raw_public_key_ex(libctx,
                                                 kem_info->keytype,
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
#if defined(SUPERVERBOSE)
    hpke_pbuf(stdout, "\tpsk_hash", psk_hash, psk_hashlen);
#endif
    kdf_info = ossl_HPKE_KDF_INFO_find_id(suite.kdf_id);
    if (kdf_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    secretlen = kdf_info->Nh;
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
    aead_info = ossl_HPKE_AEAD_INFO_find_id(suite.aead_id);
    if (aead_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    noncelen = aead_info->Nn;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_NONCE_LABEL, strlen(OSSL_HPKE_NONCE_LABEL),
                      ks_context, ks_contextlen,
                      noncelen, nonce, &noncelen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (noncelen != aead_info->Nn) {
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
    keylen = aead_info->Nk;
    erv = hpke_expand(libctx, propq, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_KEY_LABEL, strlen(OSSL_HPKE_KEY_LABEL),
                      ks_context, ks_contextlen,
                      keylen, key, &keylen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    exporterseclen = kdf_info->Nh;
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
#if defined(SUPERVERBOSE)
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
           hpke_mode_strtab[mode], mode,
           kem_info_str(kem_info), suite.kem_id,
           kdf_info_str(kdf_info), suite.kdf_id,
           aead_info_str(aead_info), suite.aead_id);
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
    OPENSSL_cleanse(ks_context, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(secret, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(nonce, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(psk_hash, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(key, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(exportersec, OSSL_HPKE_MAXSIZE);
    BIO_free_all(bfp);
    if (evppriv == NULL) { EVP_PKEY_free(skR); }
    EVP_PKEY_free(pkE);
    EVP_PKEY_free(pkI);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_clear_free(shared_secret, shared_secretlen);
    OPENSSL_free(mypub);
    return erv;
}

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
 * or might not be base64 encoded. We will try handle all those options.
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
{
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
}

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
{
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
}

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
}
