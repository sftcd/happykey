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
 * Generate keys using IKM input
 */


#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "hpke.h"

int main()
{
    /* we'll do a round-trip, generating a key, encrypting and decrypting
     * and also an encrypt to a known test vector */
    int hpke_mode=OSSL_HPKE_MODE_BASE;
    ossl_hpke_suite_st hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    /* we'll alloc all these on the stack for simplicity */
    size_t publen=OSSL_HPKE_MAXSIZE; unsigned char pub[OSSL_HPKE_MAXSIZE];
    size_t privlen=OSSL_HPKE_MAXSIZE; unsigned char priv[OSSL_HPKE_MAXSIZE];
    size_t senderpublen=OSSL_HPKE_MAXSIZE; unsigned char senderpub[OSSL_HPKE_MAXSIZE];
    size_t plainlen=OSSL_HPKE_MAXSIZE; unsigned char plain[OSSL_HPKE_MAXSIZE];
    size_t cipherlen=OSSL_HPKE_MAXSIZE; unsigned char cipher[OSSL_HPKE_MAXSIZE];
    size_t clearlen=OSSL_HPKE_MAXSIZE; unsigned char clear[OSSL_HPKE_MAXSIZE];
    size_t ikm25519len=32; unsigned char ikm25519[]={
        0x72,0x68,0x60,0x0d,0x40,0x3f,0xce,0x43,
        0x15,0x61,0xae,0xf5,0x83,0xee,0x16,0x13,
        0x52,0x7c,0xff,0x65,0x5c,0x13,0x43,0xf2,
        0x98,0x12,0xe6,0x67,0x06,0xdf,0x32,0x34
    };
    size_t ikmp256len=32; unsigned char ikmp256[]={
        0x42, 0x70, 0xe5, 0x4f, 0xfd, 0x08, 0xd7, 0x9d,
        0x59, 0x28, 0x02, 0x0a, 0xf4, 0x68, 0x6d, 0x8f,
        0x6b, 0x7d, 0x35, 0xdb, 0xe4, 0x70, 0x26, 0x5f,
        0x1f, 0x5a, 0xa2, 0x28, 0x16, 0xce, 0x86, 0x0e
    };

    if (OSSL_HPKE_kg(NULL, hpke_mode, hpke_suite, 
                     ikm25519len, ikm25519, 
                     &publen, pub, &privlen, priv)!=1)
        goto err;
    /* It's a PKCS-8 string so just print it */
    printf("%s",(char*)priv);

    publen=OSSL_HPKE_MAXSIZE;
    memset(pub,0,publen);
    privlen=OSSL_HPKE_MAXSIZE;
    memset(priv,0,privlen);
    hpke_suite.kem_id=OSSL_HPKE_KEM_ID_P256;
    if (OSSL_HPKE_kg(NULL, hpke_mode, hpke_suite, 
                     ikmp256len, ikmp256, 
                     &publen, pub, &privlen, priv)!=1)
        goto err;
    /* It's a PKCS-8 string so just print it */
    printf("%s",(char*)priv);

    return 1;
err:
    printf("Failed\n");
    return 0;
}
