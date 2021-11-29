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
#include <crypto/hpke.h>

int main()
{
    int testresult = 0;
    /* we'll do a round-trip, generating a key, encrypting and decrypting
     * and also an encrypt to a known test vector */
    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    /* we'll alloc all these on the stack for simplicity */
    size_t publen=HPKE_MAXSIZE; unsigned char pub[HPKE_MAXSIZE];
    size_t privlen=HPKE_MAXSIZE; unsigned char priv[HPKE_MAXSIZE];
    size_t senderpublen=HPKE_MAXSIZE; unsigned char senderpub[HPKE_MAXSIZE];
    size_t plainlen=HPKE_MAXSIZE; unsigned char plain[HPKE_MAXSIZE];
    size_t cipherlen=HPKE_MAXSIZE; unsigned char cipher[HPKE_MAXSIZE];
    size_t clearlen=HPKE_MAXSIZE; unsigned char clear[HPKE_MAXSIZE];
    if (hpke_kg(hpke_mode, hpke_suite,&publen, pub,&privlen, priv)!=1)
        goto err;
    memset(plain,0,HPKE_MAXSIZE);
    strcpy((char*)plain,"a message not in a bottle");
    plainlen=strlen((char*)plain);
    if (hpke_enc(hpke_mode, hpke_suite,
                NULL, 0, NULL, /* psk */
                publen, pub,
                0, NULL, NULL, /* priv */
                plainlen, plain,
                0, NULL, /* aad */
                0, NULL, /* info */
                0, NULL, /* seq */
                &senderpublen, senderpub,
                &cipherlen, cipher
#ifdef TESTVECTORS
                ,NULL
#endif
                )!=1)
        goto err;
    if (hpke_dec( hpke_mode, hpke_suite,
                NULL, 0, NULL, /* psk */
                0, NULL, /* authpub */
                privlen, priv, NULL,
                senderpublen, senderpub,
                cipherlen, cipher,
                0, NULL, /* aad */
                0, NULL, /* info */
                0, NULL, /* seq */
                &clearlen, clear)!=1)
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
