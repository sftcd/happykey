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
    int overallresult = 1;
    /* 
     * we'll do round-trips, generating a key, encrypting and decrypting 
     * for each of the many types of thing
     */
    int hpke_mode_list[]={
        HPKE_MODE_BASE,
        HPKE_MODE_PSK,
        HPKE_MODE_AUTH,
        HPKE_MODE_PSKAUTH
    };
    int mind = 0; /* index into hpke_mode_list */ 
    uint16_t hpke_kem_list[]={
        HPKE_KEM_ID_P256,
        HPKE_KEM_ID_P384,
        HPKE_KEM_ID_P521,
        HPKE_KEM_ID_25519,
        HPKE_KEM_ID_448
    };
    int kemind = 0; /* index into hpke_kem_list */
    uint16_t hpke_kdf_list[]={
        HPKE_KDF_ID_HKDF_SHA256,
        HPKE_KDF_ID_HKDF_SHA384,
        HPKE_KDF_ID_HKDF_SHA512
    };
    int kdfind = 0; 

    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t plainlen=HPKE_MAXSIZE; unsigned char plain[HPKE_MAXSIZE];

    memset(plain,0,HPKE_MAXSIZE);
    strcpy((char*)plain,"a message not in a bottle");
    plainlen=strlen((char*)plain);

    /* iterate over different modes */
    for (mind = 0; mind != (sizeof(hpke_mode_list)/sizeof(int)); mind++ ) {
        int hpke_mode = hpke_mode_list[mind];

        /* try with/without info, aad, seq */
        /* iterate over the kems, kdfs and aeads */
        for (kemind = 0; kemind != (sizeof(hpke_kem_list)/sizeof(uint16_t)); kemind++ ) {
            uint16_t kem_id=hpke_kem_list[kemind];

            hpke_suite.kem_id=kem_id;
            for (kdfind = 0; kdfind != (sizeof(hpke_kdf_list)/sizeof(uint16_t)); kdfind++ ) {
                uint16_t kdf_id=hpke_kdf_list[kdfind];

                size_t publen=HPKE_MAXSIZE; unsigned char pub[HPKE_MAXSIZE];
                size_t privlen=HPKE_MAXSIZE; unsigned char priv[HPKE_MAXSIZE];
                size_t senderpublen=HPKE_MAXSIZE; unsigned char senderpub[HPKE_MAXSIZE];

                hpke_suite.kdf_id=kdf_id;

                testresult=OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                                &publen, pub, &privlen, priv);
                if (testresult != 1) {
                    printf("OSSL_HPKE_kg fail (%d) with mode=%d,kem=0x%02x,kdf=0x%02x\n",testresult,hpke_mode,kem_id,kdf_id);
                    goto err;
                }
                size_t cipherlen=HPKE_MAXSIZE; unsigned char cipher[HPKE_MAXSIZE];
                size_t clearlen=HPKE_MAXSIZE; unsigned char clear[HPKE_MAXSIZE];
                testresult=OSSL_HPKE_enc(testctx, hpke_mode, hpke_suite,
                    NULL, 0, NULL, /* psk */
                    publen, pub, 
                    0, NULL, NULL, /* auth priv */
                    plainlen, plain,
                    0, NULL, /* aad */
                    0, NULL, /* info */
                    0, NULL, /* seq */
                    &senderpublen, senderpub,
                    &cipherlen, cipher);
                if (testresult != 1) {
                    printf("OSSL_HPKE_enc fail (%d) with mode=%d,kem=0x%02x,kdf=0x%02x\n",testresult,hpke_mode,kem_id,kdf_id);
                    goto err;
                }
                testresult=OSSL_HPKE_dec(testctx, hpke_mode, hpke_suite,
                    NULL, 0, NULL, /* psk */
                    0, NULL, /* auth pub */
                    privlen, priv, NULL,
                    senderpublen, senderpub,
                    cipherlen, cipher,
                    0, NULL, /* aad */
                    0, NULL, /* info */
                    0, NULL, /* seq */
                    &clearlen, clear);
                if (testresult != 1) {
                    printf("OSSL_HPKE_dec fail (%d) with mode=%d,kem=0x%02x,kdf=0x%02x\n",testresult,hpke_mode,kem_id,kdf_id);
                    goto err;
                }
                /* check output */
                if (clearlen!=plainlen) {
                    printf("clearlen!=plainlen fail (%d) with mode=%d,kem=0x%02x,kdf=0x%02x\n",testresult,hpke_mode,kem_id,kdf_id);
                    goto err;
                }
                if (memcmp(clear,plain,plainlen)) {
                    printf("mamcmp(clearlen,plainlen) fail (%d) with mode=%d,kem=0x%02x,kdf=0x%02x\n",testresult,hpke_mode,kem_id,kdf_id);
                    goto err;
                }
                printf("test success with mode=%d,kem=0x%02x,kdf=0x%02x\n",hpke_mode,kem_id,kdf_id);
                continue;
err:
                if (testresult != 1) {
                    printf("test fail with mode=%d,kem=0x%02x,kdf=0x%02x\n",hpke_mode,kem_id,kdf_id);
                    overallresult = 0;
                }
            }
        }
    }

    /* yay, success */
    testresult = 1;
    return overallresult;
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

    /*
     * Init OpenSSL stuff - copied from lighttpd
     */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
                    |OPENSSL_INIT_LOAD_CRYPTO_STRINGS,NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                       |OPENSSL_INIT_ADD_ALL_DIGESTS
                       |OPENSSL_INIT_LOAD_CONFIG, NULL);

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

    return(overallreturn);
}

