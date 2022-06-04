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
 * API tests that can be integrated with OpenSSL ``make test`` target
 */

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "hpke.h"

#ifdef TESTVECTORS
#include "hpketv.h"
#endif

static int verbose=0; ///< global var for verbosity

static OSSL_LIB_CTX *testctx = NULL;

static void usage(char *prog,char *errmsg) 
{
    if (errmsg) fprintf(stderr,"\nError! %s\n\n",errmsg);
    fprintf(stderr,"HPKE (RFC9180) API tester, options are:\n");
    fprintf(stderr,"\t-v verbose output\n");
    fprintf(stderr,"\n");
    if (errmsg==NULL) {
        exit(0);
    } else {
        exit(1);
    }
}

static int test_hpke(void)
{
    int testresult = 0;
    /* we'll do a round-trip, generating a key, encrypting and decrypting */
    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    /* we'll alloc all these on the stack for simplicity */
    size_t publen=HPKE_MAXSIZE; unsigned char pub[HPKE_MAXSIZE];
    size_t privlen=HPKE_MAXSIZE; unsigned char priv[HPKE_MAXSIZE];
    size_t senderpublen=HPKE_MAXSIZE; unsigned char senderpub[HPKE_MAXSIZE];
    size_t plainlen=HPKE_MAXSIZE; unsigned char plain[HPKE_MAXSIZE];
    size_t cipherlen=HPKE_MAXSIZE; unsigned char cipher[HPKE_MAXSIZE];
    size_t clearlen=HPKE_MAXSIZE; unsigned char clear[HPKE_MAXSIZE];

    memset(plain,0,HPKE_MAXSIZE);
    strcpy((char*)plain,"a message not in a bottle");
    plainlen=strlen((char*)plain);

    if (OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                &publen, pub, &privlen, priv)!=1)
        goto err;
    if (OSSL_HPKE_enc(testctx, hpke_mode, hpke_suite,
                NULL, 0, NULL, /* psk */
                publen, pub, 
                0, NULL, NULL, /* auth priv */
                plainlen, plain,
                0, NULL, /* aad */
                0, NULL, /* info */
                0, NULL, /* seq */
                &senderpublen, senderpub,
                &cipherlen, cipher)!=1)
        goto err;

    if (OSSL_HPKE_dec(testctx, hpke_mode, hpke_suite,
                NULL, 0, NULL, /* psk */
                0, NULL, /* auth pub */
                privlen, priv, NULL,
                senderpublen, senderpub,
                cipherlen, cipher,
                0, NULL, /* aad */
                0, NULL, /* info */
                0, NULL, /* seq */
                &clearlen, clear)!=1)
        goto err;

    /* check output */
    if (clearlen!=plainlen)
        goto err;

    if (memcmp(clear,plain,plainlen))
        goto err;

    /* yay, success */
    testresult = 1;
err:
    return testresult;
}

/*!
 * @brief hey it's main()
 */
int main(int argc, char **argv)
{
    int overallreturn=0;
    int apires=1;
    int doing_grease=1;
    int opt;
    while((opt = getopt(argc, argv, "?hv")) != -1) {
        switch(opt) {
            case '?': usage(argv[0],"Unexpected option"); break;
            case 'v': verbose++; break;
            default:
                usage(argv[0],"unknown arg");
        }
    }

    apires=test_hpke();
    if (apires==1) {
        printf("API test success\n");
    } else {
        printf("API test fail (%d)\n",apires);
    }

    /* if we're just greasing get that out of the way and exit */
    if (doing_grease==1) {
        hpke_suite_t g_suite;
        unsigned char g_pub[HPKE_MAXSIZE];
        size_t g_pub_len=HPKE_MAXSIZE;
        unsigned char g_cipher[HPKE_MAXSIZE];
        size_t g_cipher_len=266;

        if (OSSL_HPKE_good4grease(NULL,g_suite,g_pub,&g_pub_len,g_cipher,g_cipher_len)!=1) {
            printf("OSSL_HPKE_good4grease failed, bummer\n");
        } else {
            printf("OSSL_HPKE_good4grease worked, yay! (use debugger or SUPERVERBOSE to see what it does:-)\n");
        }
        return(1);
    }

    /*
     * Init OpenSSL stuff - copied from lighttpd
     */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
                    |OPENSSL_INIT_LOAD_CRYPTO_STRINGS,NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                       |OPENSSL_INIT_ADD_ALL_DIGESTS
                       |OPENSSL_INIT_LOAD_CONFIG, NULL);

    return(overallreturn);
}

