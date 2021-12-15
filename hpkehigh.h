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
 * Sketch of a higher level API for HPKE
 */

#ifndef HPKEHIGH_H_INCLUDED

/* 
 * Context handling - mostly the context holds the mode
 * and private value(s)
 */
HPKE_CTX* HPKE_CTX_new(OSSL_LIB_CTX *libctx)
void HPKE_CTX_free(HPKE_CTX* ctx);

/* 
 * Set private values in context - note that we may need
 * buffer equivalents for each of these that can use
 * OSSL_PARAMs instead.
 */
/* set the private value for HPKE_Decrypt to use */
int HPKE_CTX_set_recippriv(HPKE_CTX* ctx, EVP_PKEY *priv);
/* set the private auth value for HPKE_Encrypt to use */
int HPKE_CTX_set_authpriv(HPKE_CTX* ctx, EVP_PKEY *priv);
/* set the private value for HPKE_Encrypt to use, if we need
 * to make >1 encrypt call with the same private value */
int HPKE_CTX_set_senderpriv(HPKE_CTX* ctx, EVP_PKEY *priv);

/* allow caller to know output sizes, needed for GREASEing */
size_t HPKE_CTX_get_cipher_size(HPKE_CTX* ctx, size_t in_size);
size_t HPKE_CTX_get_enc_size(HPKE_CTX* ctx);

/* 
 * Params: HPKE mode, private or public octet strings, psks - basically
 * set things that don't change for every call to HPKE_Encrypt() 
 * or HPKE_Decrypt()
 */
int HPKE_CTX_set_params(HPKE_CTX* ctx, OSSL_PARAM *p);
#define OSSL_HPKE_PARAM_MODE       1 /* int */
#define OSSL_HPKE_PARAM_PSKID      2 /* string */
#define OSSL_HPKE_PARAM_PSK        3 /* octet string */
#define OSSL_HPKE_PARAM_AUTHPUB    4 /* octet string */
#define OSSL_HPKE_PARAM_SENDERPRIV 5 /* octet string */
#define OSSL_HPKE_PARAM_AUTHPRIV   6 /* octet string */
#define OSSL_HPKE_PARAM_RECIPPRIV  7 /* octet string */

int HPKE_Encrypt(HPKE_CTX* ctx, 
        /* suite, recippub from e.g. HTTPS RR in DNS */
        hpke_suite_t suite, size_t recippub_len, unsigned char *recippub,
        /* plain, aad, info from applictation */
        size_t plain_len, unsigned char *plain,
        size_t aad_len, unsigned char *aad,
        size_t info_len, unsigned char *info
        /* seq from application if 2nd use of recippub */
        size_t seq_len, unsigned char *seq,
        /* outputs */
        size_t *senderpub_len, unsigned char *senderpub,
        size_t *cipher_len, unsigned char *cipher);

int HPKE_Decrypt(HPKE_CTX* ctx, hpke_suite_t suite,
        /* enc, cipher from protocol */
        size_t cipher_len, unsigned char *cipher,
        size_t senderpub_len, unsigned char *senderpub,
        /* aad, info from applictation */
        size_t aad_len, unsigned char *aad,
        size_t info_len, unsigned char *info
        /* seq from application if 2nd use of recippub */
        size_t seq_len, unsigned char *seq,
        /* outputs */
        size_t *plain_len, unsigned char *plain);

/* 
 * An API for new HPKE suites based on supported algorithms.
 * After some investigation, this may well be a bad idea.
 * Mapping from names to all the HPKE length params is
 * likely non-trivial, and a lack of test vectors may
 * result in a lack of interop, so better for new suites
 * to be done via forks then PRs to upstream once those 
 * putative new suites are documented in RFCs.   
 */
int HPKE_set_codepoint(hpke_suite_t suite, 
        const char *aead_name, /* e.g. AES-128-GCM */
        const char *kem_type, /* e.g. "EC" or "X25519" or "X448" */
        const char *kem_groupname, /* only for NIST curves, e.g. "P-256" */
        const char *kem_hash, /* e.g. SHA256 */
        const char *kdf_name /* e.g. HKDF-SHA256 */
        );
#endif

#ifdef SENDERFRAGMENT
    HPKE_CTX *sender=NULL;
    OSSL_PARAM params[3], *p = params;
    int mode=HPKE_MODE_BASE;
    hpke_suite_t suite=HPKE_DEFAULT_SUITE;
    unsigned char encpublic[HPKE_MAXSIZE]; size_t encpubliclen=HPKE_MAXSIZE;;
    unsigned char plain[HPKE_MAXSIZE]; size_t plainlen=HPKE_MAXSIZE;;
    unsigned char aad[HPKE_MAXSIZE]; size_t aadlen=HPKE_MAXSIZE;;
    unsigned char cipher[HPKE_MAXSIZE]; size_t cipherlen=HPKE_MAXSIZE;;
    size_t lciphelen=0;
    unsigned char enc[HPKE_MAXSIZE]; size_t enclen=HPKE_MAXSIZE;;

    sender=HPKE_CTX_new(hpke_libctx);
    if (!sender) goto err;
    *p++ = OSSL_PARAM_construct_int(OSSL_HPKE_PARAM_MODE, &mode);
    *p = OSSL_PARAM_construct_end();
    if (HPKE_CTX_set_params(sender, params) <= 0) goto err;
    lcipherlen = HPKE_CTX_get_cipher_size(sender, plainlen);
    if (lcipherlen > cipherlen ) goto err;
    lcipherlen = HPKE_CTX_get_enc_size(sender);
    if (lenclen > enclen ) goto err;
    if (HPKE_CTX_Encrypt(sender, suite,
                encpublic, encpubliclen,
                plain, plainlen,
                aad, aadlen,
                NULL, 0, /* info */
                NULL, 0, /* seq */
                enc, &enclen,
                cipher, &cipherlen)!= 1) goto err;
    /* send enc, cipher, then clean up */
    HPKE_CTX_free(sender);
#endif

#ifdef RECIPFRAGMENT
    HPKE_CTX *recip=NULL;
    OSSL_PARAM params[4], *p = params;
    EVP_PKEY *decpriv=something;
    int mode=HPKE_MODE_BASE;
    hpke_suite_t suite=HPKE_DEFAULT_SUITE;
    unsigned char plain[HPKE_MAXSIZE]; size_t plainlen=HPKE_MAXSIZE;;
    unsigned char aad[HPKE_MAXSIZE]; size_t aadlen=HPKE_MAXSIZE;;
    unsigned char cipher[HPKE_MAXSIZE]; size_t cipherlen=HPKE_MAXSIZE;;
    unsigned char authpub[HPKE_MAXSIZE]; size_t authpublen=HPKE_MAXSIZE;;
    unsigned char enc[HPKE_MAXSIZE]; size_t enclen=HPKE_MAXSIZE;;

    recip=HPKE_CTX_new(hpke_libctx);
    if (!recip) goto err;
    *p++ = OSSL_PARAM_construct_int(OSSL_KPKE_PARAM_MODE, &mode);
    *p = OSSL_PARAM_construct_end();
    if (HPKE_CTX_set_params(recip, params) <= 0) goto err;

    if (HPKE_CTX_set_decpriv(recip, decpriv) <= 0) goto err;
    if (HPKE_CTX_Decrypt(recip, suite,
                enc, enclen,
                cipher, cipherlen,
                plain, plainlen,
                aad, aadlen,
                NULL, 0, /* info */
                NULL, 0, /* seq */
                plain, plainlen)!=1) goto err;
    HPKE_CTX_free(recip);
#endif

