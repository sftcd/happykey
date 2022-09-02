/*
 * Copyright 2021 Stephen Farrell. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file
 *
 * A place to play with code to be added to OpenSSL make test target
 */


#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "hpke.h"

#ifndef OSSL_HPKE_MAXSIZE
#define OSSL_HPKE_MAXSIZE 1024
#endif
#ifndef OSSL_HPKE_DEFSIZE
#define OSSL_HPKE_DEFSIZE (4 * 1024)
#endif

int main()
{
    int testresult = 0;
    /* we'll do a round-trip, generating a key, encrypting and decrypting
     * and also an encrypt to a known test vector */
    int hpke_mode=OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    /* we'll alloc all these on the stack for simplicity */
    size_t publen=OSSL_HPKE_MAXSIZE; unsigned char pub[OSSL_HPKE_MAXSIZE];
    EVP_PKEY *privp = NULL;
    size_t senderpublen=OSSL_HPKE_MAXSIZE; unsigned char senderpub[OSSL_HPKE_MAXSIZE];
    size_t plainlen=OSSL_HPKE_MAXSIZE; unsigned char plain[OSSL_HPKE_MAXSIZE];
    size_t cipherlen=OSSL_HPKE_MAXSIZE; unsigned char cipher[OSSL_HPKE_MAXSIZE];
    size_t clearlen=OSSL_HPKE_MAXSIZE; unsigned char clear[OSSL_HPKE_MAXSIZE];
    size_t ikmlen=OSSL_HPKE_MAXSIZE; unsigned char ikm[OSSL_HPKE_MAXSIZE];

#ifdef TRYDET
    hpke_suite.kem_id=OSSL_HPKE_KEM_ID_P521;
    memset(ikm,0,ikmlen);
    if (OSSL_HPKE_keygen_buf(NULL, NULL, hpke_mode, hpke_suite,
                             ikm, ikmlen, pub, &publen, priv, &privlen)!=1)
        goto err;
#else
    if (OSSL_HPKE_keygen(NULL, NULL, hpke_mode, hpke_suite,
                         NULL, 0, pub, &publen, &privp)!=1)
        goto err;
#endif
    memset(plain,0,OSSL_HPKE_MAXSIZE);
    strcpy((char*)plain,"a message not in a bottle");
    plainlen=strlen((char*)plain);
    if (OSSL_HPKE_enc(NULL, NULL, hpke_mode, hpke_suite,
                NULL, NULL, 0,/* psk */
                pub, publen,
                NULL, 0, NULL, /* priv */
                plain, plainlen,
                NULL, 0, /* aad */
                NULL, 0, /* info */
                NULL, 0, /* seq */
                senderpub, &senderpublen, NULL,
                cipher, &cipherlen
#ifdef TESTVECTORS
                ,NULL
#endif
                )!=1)
        goto err;
    if (OSSL_HPKE_dec(NULL, NULL, hpke_mode, hpke_suite,
                NULL, NULL, 0, /* psk */
                NULL, 0, /* authpub */
                NULL, 0, privp,
                senderpub, senderpublen,
                cipher, cipherlen,
                NULL, 0, /* aad */
                NULL, 0, /* info */
                NULL, 0, /* seq */
                clear, &clearlen)!=1)
        goto err;
    if (clearlen!=plainlen) 
        goto err;
    if (memcmp(clear,plain,plainlen))
        goto err;
    /* yay, success */
    testresult = 1;
    printf("Worked ok\n");
err:
    if (testresult==0) printf("Failed\n");
    return testresult;
}
