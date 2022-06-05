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
#include <openssl/rand.h>

#include "hpke.h"

#ifdef TESTVECTORS
#include "hpketv.h"
#endif

static int verbose=0; ///< global var for verbosity

static OSSL_LIB_CTX *testctx = NULL;

static int test_true( char *file, int line, int res, char *str);

/*
 * @brief mimic OpenSSL test_true macro
 */
#define TEST_true(__x__, __str__) test_true(__FILE__, __LINE__, __x__, __str__)

/*
 * Randomly toss a coin
 */
static unsigned char rb = 0;

#define COINISHEADS (RAND_bytes(&rb,1) && rb%2)

static void usage(char *prog,char *errmsg) 
{
    if (errmsg) printf("\nError! %s\n\n",errmsg);
    fprintf(stderr,"HPKE (RFC9180) API tester, options are:\n");
    fprintf(stderr,"\t-v verbose output\n");
    fprintf(stderr,"\n");
    if (errmsg==NULL) {
        exit(0);
    } else {
        exit(1);
    }
}

/*
 * @brief mimic OpenSSL test_true function
 */
static int test_true( char *file, int line, int res, char *str)
{
    if (res != 1) {
        printf("Fail: %s at %s:%d, res: %d\n", str, file, line, res);
    } else if (verbose) {
        printf("Success: %s at %s:%d, res: %d\n", str, file, line, res);
    }
    return (res);
}

static int test_hpke(void)
{
    int testresult = 0;
    int overallresult = 1;
    /* 
     * we'll do round-trips, generating a key, encrypting and decrypting 
     * for each of the many types of thing
     */
    int hpke_mode_list[] = {
        HPKE_MODE_BASE,
        HPKE_MODE_PSK,
        HPKE_MODE_AUTH,
        HPKE_MODE_PSKAUTH
    };
    int mind = 0; /* index into hpke_mode_list */ 
    uint16_t hpke_kem_list[] = {
        HPKE_KEM_ID_P256,
        HPKE_KEM_ID_P384,
        HPKE_KEM_ID_P521,
        HPKE_KEM_ID_25519,
        HPKE_KEM_ID_448
    };
    int kemind = 0; /* index into hpke_kem_list */
    uint16_t hpke_kdf_list[] = {
        HPKE_KDF_ID_HKDF_SHA256,
        HPKE_KDF_ID_HKDF_SHA384,
        HPKE_KDF_ID_HKDF_SHA512
    };
    int kdfind = 0; 
    uint16_t hpke_aead_list[] = {
        HPKE_AEAD_ID_AES_GCM_128,
        HPKE_AEAD_ID_AES_GCM_256,
        HPKE_AEAD_ID_CHACHA_POLY1305
    };
    int aeadind = 0;

    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t plainlen=HPKE_MAXSIZE; unsigned char plain[HPKE_MAXSIZE];

    memset(plain,0,HPKE_MAXSIZE);
    strcpy((char*)plain,"a message not in a bottle");
    plainlen=strlen((char*)plain);

    /* iterate over different modes */
    for (mind = 0; mind != (sizeof(hpke_mode_list)/sizeof(int)); mind++ ) {
        int hpke_mode = hpke_mode_list[mind];
        size_t aadlen = HPKE_MAXSIZE; unsigned char aad[HPKE_MAXSIZE];
        unsigned char *aadp = NULL;
        size_t infolen=HPKE_MAXSIZE; unsigned char info[HPKE_MAXSIZE];
        unsigned char *infop = NULL;
        size_t seqlen=12; unsigned char seq[12];
        unsigned char *seqp = NULL;
        size_t psklen=HPKE_MAXSIZE; unsigned char psk[HPKE_MAXSIZE];
        unsigned char *pskp = NULL;
        char pskid[HPKE_MAXSIZE]; char *pskidp = NULL;

        /* 
         * We randomly try with/without info, aad, seq. The justification is
         * that given the mode and suite combos, and this being run even a
         * few times, we'll exercise all the code paths quickly.
         * We don't really care what the values are but it'll be easier to
         * debug if they're known, so we set 'em.
         */
        if (COINISHEADS) {
            aadp = aad; memset(aad,aadlen,'a');
        } else {
            aadlen = 0;
        } 
        if (COINISHEADS) {
            infop = info; memset(info,infolen,'i');
        } else {
            infolen = 0;
        } 
        if (COINISHEADS) {
            seqp = seq; memset(seq,seqlen,'s');
        } else {
            seqlen = 0;
        } 

        if ((hpke_mode == HPKE_MODE_PSK) || (hpke_mode == HPKE_MODE_PSKAUTH)){
            pskp = psk; memset(psk, psklen, 'P');
            pskidp = pskid; memset(pskid, HPKE_MAXSIZE-1, 'I'); pskid[HPKE_MAXSIZE-1]='\0';
        } else {
            psklen = 0;
        }

        /* iterate over the kems, kdfs and aeads */
        for (kemind = 0; kemind != (sizeof(hpke_kem_list)/sizeof(uint16_t)); kemind++ ) {
            uint16_t kem_id=hpke_kem_list[kemind];
            size_t authpublen=HPKE_MAXSIZE; unsigned char authpub[HPKE_MAXSIZE];
            unsigned char *authpubp = NULL;
            size_t authprivlen=HPKE_MAXSIZE; unsigned char authpriv[HPKE_MAXSIZE];
            unsigned char *authprivp = NULL;

            hpke_suite.kem_id=kem_id;

            /* can only set AUTH key pair when we know KEM */
            if ((hpke_mode == HPKE_MODE_AUTH) || (hpke_mode == HPKE_MODE_PSKAUTH)){
                if (TEST_true(OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                            &authpublen, authpub, &authprivlen, authpriv),"OSS_HPKE_kg") != 1) {
                    goto err;
                }
                authpubp = authpub;
                authprivp = authpriv;
            } else {
                authpublen = 0;
                authprivlen = 0;
            }

            for (kdfind = 0; kdfind != (sizeof(hpke_kdf_list)/sizeof(uint16_t)); kdfind++ ) {
                uint16_t kdf_id=hpke_kdf_list[kdfind];

                hpke_suite.kdf_id=kdf_id;

                for (aeadind = 0; aeadind != (sizeof(hpke_aead_list)/sizeof(uint16_t)); aeadind++ ) {
                    uint16_t aead_id=hpke_aead_list[aeadind];
                    size_t publen=HPKE_MAXSIZE; unsigned char pub[HPKE_MAXSIZE];
                    size_t privlen=HPKE_MAXSIZE; unsigned char priv[HPKE_MAXSIZE];
                    size_t senderpublen=HPKE_MAXSIZE; unsigned char senderpub[HPKE_MAXSIZE];
                    size_t cipherlen=HPKE_MAXSIZE; unsigned char cipher[HPKE_MAXSIZE];
                    size_t clearlen=HPKE_MAXSIZE; unsigned char clear[HPKE_MAXSIZE];

                    hpke_suite.aead_id=aead_id;
                    if (verbose) {
                        printf("mode=%d,kem=0x%02x,kdf=0x%02x,aead=0x%02x\n",
                            hpke_mode,kem_id,kdf_id,aead_id);
                    }
                    if (TEST_true(OSSL_HPKE_kg(testctx, hpke_mode, hpke_suite,
                                &publen, pub, &privlen, priv),"OSS_HPKE_kg") != 1) {
                        goto err;
                    }
                    if (TEST_true(OSSL_HPKE_enc(testctx, hpke_mode, hpke_suite,
                        pskp, psklen, pskidp, /* psk */
                        publen, pub, 
                        authprivlen, authprivp, NULL, /* auth priv */
                        plainlen, plain,
                        aadlen, aadp, /* aad */
                        infolen, infop, /* info */
                        seqlen, seqp, /* seq */
                        &senderpublen, senderpub,
                        &cipherlen, cipher),"OSSL_HPKE_enc") != 1) {
                            goto err;
                    }
                    if (TEST_true(OSSL_HPKE_dec(testctx, hpke_mode, hpke_suite,
                        pskp, psklen, pskidp, /* psk */
                        authpublen, authpubp, /* auth pub */
                        privlen, priv, NULL,
                        senderpublen, senderpub,
                        cipherlen, cipher,
                        aadlen, aadp, /* aad */
                        infolen, infop, /* info */
                        seqlen, seqp, /* seq */
                        &clearlen, clear),"OSSL_HPKE_dec") != 1) {
                            goto err;
                    }
                    /* check output */
                    if (clearlen!=plainlen) {
                        printf("clearlen!=plainlen fail\n");
                        goto err;
                    }
                    if (memcmp(clear,plain,plainlen)) {
                        printf("memcmp(clearlen,plainlen) fail\n");
                        goto err;
                    }
                    if (verbose) {
                        printf("test success\n");
                    }
                    continue;
err:
                    overallresult = 0;
                }
            }
        }
    }

    if (overallresult == 1) {
        /* try GREASEing API */
        hpke_suite_t g_suite;
        unsigned char g_pub[HPKE_MAXSIZE];
        size_t g_pub_len=HPKE_MAXSIZE;
        unsigned char g_cipher[HPKE_MAXSIZE];
        size_t g_cipher_len=266;
        if (TEST_true(OSSL_HPKE_good4grease(NULL,g_suite,g_pub,&g_pub_len,g_cipher,g_cipher_len),"good4grease")!=1) {
            goto moarerr;
        }
    }
    /* yay, success */
    return overallresult;
moarerr:
    /* bummer */
    overallresult=0;
    return overallresult;
}

/*!
 * @brief hey it's main()
 */
int main(int argc, char **argv)
{
    int apires=1;
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

    return(apires);
}

