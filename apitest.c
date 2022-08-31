#ifdef HAPPYKEY
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

# include <stddef.h>
# include <stdio.h>
# include <stdint.h>
# include <stdlib.h>
# include <string.h>
# include <getopt.h>
# include <ctype.h>

# include <openssl/evp.h>
# include <openssl/ssl.h>
# include <openssl/rand.h>
# include "hpke.h"

static int verbose = 0;
static OSSL_LIB_CTX *testctx = NULL;

extern int OSSL_HPKE_prbuf2evp(OSSL_LIB_CTX *libctx, const char *propq,
                        unsigned int kem_id,
                        const unsigned char *prbuf, size_t prbuf_len,
                        const unsigned char *pubuf, size_t pubuf_len,
                        EVP_PKEY **priv);

/*
 * @brief mimic OpenSSL test_true function
 */
static int test_true(char *file, int line, int res, char *str)
{
    if (res != 1) {
        printf("Fail: %s at %s:%d, res: %d\n", str, file, line, res);
    } else if (verbose) {
        printf("Success: %s at %s:%d, res: %d\n", str, file, line, res);
    }
    return res;
}
/*
 * @brief mimic OpenSSL test_false function
 */
static int test_false(char *file, int line, int res, char *str)
{
    if (!res) {
        if (verbose) {
            printf("Expected fail: %s at %s:%d, res: %d\n", str, 
                    file, line, res);
        }
        return 1;
    } 
    printf("Unexpected success = Fail: %s at %s:%d, res: %d\n", str, 
            file, line, res);
    return 0;
}
static void usage(char *prog, char *errmsg)
{
    if (errmsg)
        fprintf(stderr, "\nError! %s\n\n", errmsg);
    fprintf(stderr, "HPKE (RFC9180) API tester, options are:\n");
    fprintf(stderr, "\t-v verbose output\n");
    fprintf(stderr, "\n");
    if (errmsg == NULL) {
        exit(0);
    } else {
        exit(1);
    }
}

/*
 * @brief mimic OpenSSL test_true macro
 */
# define OSSL_HPKE_TEST_true(__x__, __str__) \
    test_true(__FILE__, __LINE__, __x__, __str__)
# define OSSL_HPKE_TEST_false(__x__, __str__) \
    test_false(__FILE__, __LINE__, __x__, __str__)
#else
# define OSSL_HPKE_TEST_true(__x__, __str__) TEST_int_eq(__x__, 1)
# define OSSL_HPKE_TEST_false(__x__, __str__) TEST_false(__x__)
#endif

#ifndef OSSL_HPKE_MAXSIZE
#define OSSL_HPKE_MAXSIZE 1024
#endif
#ifndef OSSL_HPKE_DEFSIZE
#define OSSL_HPKE_DEFSIZE (4 * 1024)
#endif

/*
 * Randomly toss a coin
 */
static unsigned char rb = 0;
# define COIN_IS_HEADS (RAND_bytes_ex(testctx, &rb, 1, 10) && rb % 2)

/* tables of HPKE modes and suite values */
static int hpke_mode_list[] = {
    OSSL_HPKE_MODE_BASE,
    OSSL_HPKE_MODE_PSK,
    OSSL_HPKE_MODE_AUTH,
    OSSL_HPKE_MODE_PSKAUTH
};
static uint16_t hpke_kem_list[] = {
    OSSL_HPKE_KEM_ID_P256,
    OSSL_HPKE_KEM_ID_P384,
    OSSL_HPKE_KEM_ID_P521,
    OSSL_HPKE_KEM_ID_25519,
    OSSL_HPKE_KEM_ID_448
};
static uint16_t hpke_kdf_list[] = {
    OSSL_HPKE_KDF_ID_HKDF_SHA256,
    OSSL_HPKE_KDF_ID_HKDF_SHA384,
    OSSL_HPKE_KDF_ID_HKDF_SHA512
};
static uint16_t hpke_aead_list[] = {
    OSSL_HPKE_AEAD_ID_AES_GCM_128,
    OSSL_HPKE_AEAD_ID_AES_GCM_256,
    OSSL_HPKE_AEAD_ID_CHACHA_POLY1305
};

/* strings that can be used, with names or IANA codepoints */
static char *kem_str_list[] = { 
    "P-256", "P-384", "P-521", "x25519", "x448", 
    "0x10", "0x11", "0x12", "0x20", "0x21", 
    "16", "17", "18", "32", "33"
};
static char *kdf_str_list[] = {
    "hkdf-sha256", "hkdf-sha384", "hkdf-sha512", 
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03", 
    "1", "2", "3" 
};
static char *aead_str_list[] = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", 
    "0x1", "0x01", "0x2", "0x02", "0x3", "0x03", 
    "1", "2", "3" 
};
/* table of bogus strings that better not work */
static char *bogus_suite_strs[] = {
    "3,33,3",
    "bogus,bogus,bogus",
    "bogus,33,3,1,bogus",
    "bogus,33,3,1",
    "bogus,bogus",
    "bogus",
};

/**
 * @brief round-trips, generating keys, encrypt and decrypt
 *
 * This iterates over all mode and ciphersuite options trying
 * a key gen, encrypt and decrypt for each. The aad, info, and
 * seq inputs are randomly set or omitted each time. EVP and
 * non-EVP key generation are randomly selected.
 *
 * @return 1 for success, other otherwise
 */
static int test_hpke_modes_suites(void)
{
    int overallresult = 1;
    int mind = 0; /* index into hpke_mode_list */
    int kemind = 0; /* index into hpke_kem_list */
    int kdfind = 0; /* index into hpke_kdf_list */
    int aeadind = 0; /* index into hpke_aead_list */

    /* iterate over the different modes */
    for (mind = 0; mind != (sizeof(hpke_mode_list) / sizeof(int)); mind++) {
        int hpke_mode = hpke_mode_list[mind];
        size_t aadlen = OSSL_HPKE_MAXSIZE;
        unsigned char aad[OSSL_HPKE_MAXSIZE];
        unsigned char *aadp = NULL;
        size_t infolen = OSSL_HPKE_MAXSIZE;
        unsigned char info[OSSL_HPKE_MAXSIZE];
        unsigned char *infop = NULL;
        size_t seqlen = 12;
        unsigned char seq[12];
        unsigned char *seqp = NULL;
        size_t psklen = OSSL_HPKE_MAXSIZE;
        unsigned char psk[OSSL_HPKE_MAXSIZE];
        unsigned char *pskp = NULL;
        char pskid[OSSL_HPKE_MAXSIZE];
        char *pskidp = NULL;
        EVP_PKEY *privp = NULL;
        OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
        size_t plainlen = OSSL_HPKE_MAXSIZE;
        unsigned char plain[OSSL_HPKE_MAXSIZE];

        memset(plain, 0x00, OSSL_HPKE_MAXSIZE);
        strcpy((char *)plain, "a message not in a bottle");
        plainlen = strlen((char *)plain);
        /*
         * Randomly try with/without info, aad, seq. Given mode and suite
         * combos, and this being run even a few times, we'll exercise many
         * code paths fairly quickly. We don't really care what the values
         * are but it'll be easier to debug if they're known, so we set 'em.
         */
        if (COIN_IS_HEADS) {
#ifdef HAPPYKEY
            if (verbose) { printf("adding aad,"); }
#endif
            aadp = aad;
            memset(aad, 'a', aadlen);
        } else {
#ifdef HAPPYKEY
            if (verbose) { printf("not adding aad,"); }
#endif
            aadlen = 0;
        }
        if (COIN_IS_HEADS) {
#ifdef HAPPYKEY
            if (verbose) { printf("adding info,"); }
#endif
            infop = info;
            memset(info, 'i', infolen);
        } else {
#ifdef HAPPYKEY
            if (verbose) { printf("not adding info,"); }
#endif
            infolen = 0;
        }
        if (COIN_IS_HEADS) {
#ifdef HAPPYKEY
            if (verbose) { printf("adding seq\n"); }
#endif
            seqp = seq;
            memset(seq, 's', seqlen);
        } else {
#ifdef HAPPYKEY
            if (verbose) { printf("not adding seq\n"); }
#endif
            seqlen = 0;
        }
        if (hpke_mode == OSSL_HPKE_MODE_PSK
            || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
            pskp = psk;
            memset(psk, 'P', psklen);
            pskidp = pskid;
            memset(pskid, 'I', OSSL_HPKE_MAXSIZE - 1);
            pskid[OSSL_HPKE_MAXSIZE - 1] = '\0';
        } else {
            psklen = 0;
        }
        /* iterate over the kems, kdfs and aeads */
        for (kemind = 0;
             overallresult == 1 &&
             kemind != (sizeof(hpke_kem_list) / sizeof(uint16_t));
             kemind++) {
            uint16_t kem_id = hpke_kem_list[kemind];
            size_t authpublen = OSSL_HPKE_MAXSIZE;
            unsigned char authpub[OSSL_HPKE_MAXSIZE];
            unsigned char *authpubp = NULL;
            EVP_PKEY *authpriv_evp = NULL;

            hpke_suite.kem_id = kem_id;
            /* can only set AUTH key pair when we know KEM */
            if ((hpke_mode == OSSL_HPKE_MODE_AUTH) ||
                (hpke_mode == OSSL_HPKE_MODE_PSKAUTH)) {
                if (OSSL_HPKE_TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                                         hpke_mode,
                                                         hpke_suite,
                                                         NULL, 0,
                                                         authpub,
                                                         &authpublen,
                                                         &authpriv_evp),
                                        "OSS_OSSL_HPKE_keygen") != 1) {
                    overallresult = 0;
                }
                authpubp = authpub;
            } else {
                authpublen = 0;
            }
            for (kdfind = 0;
                 overallresult == 1 &&
                 kdfind != (sizeof(hpke_kdf_list) / sizeof(uint16_t));
                 kdfind++) {
                uint16_t kdf_id = hpke_kdf_list[kdfind];

                hpke_suite.kdf_id = kdf_id;
                for (aeadind = 0;
                     overallresult == 1 &&
                     aeadind != (sizeof(hpke_aead_list) / sizeof(uint16_t));
                     aeadind++) {
                    uint16_t aead_id = hpke_aead_list[aeadind];
                    size_t publen = OSSL_HPKE_MAXSIZE;
                    unsigned char pub[OSSL_HPKE_MAXSIZE];
                    size_t senderpublen = OSSL_HPKE_MAXSIZE;
                    unsigned char senderpub[OSSL_HPKE_MAXSIZE];
                    size_t cipherlen = OSSL_HPKE_MAXSIZE;
                    unsigned char cipher[OSSL_HPKE_MAXSIZE];
                    size_t clearlen = OSSL_HPKE_MAXSIZE;
                    unsigned char clear[OSSL_HPKE_MAXSIZE];

                    hpke_suite.aead_id = aead_id;
#ifdef HAPPYKEY
                    if (verbose) {
                        printf("mode=%d,kem=0x%02x,kdf=0x%02x,aead=0x%02x\n",
                               hpke_mode, kem_id, kdf_id, aead_id);
                    }
#endif
                    if (OSSL_HPKE_TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                                             hpke_mode,
                                                             hpke_suite,
                                                             NULL, 0,
                                                             pub, &publen,
                                                             &privp),
                                            "OSSL_HPKE_keygen") != 1) {
                        overallresult = 0;
                    }

#define NEWAPI
#ifdef NEWAPI
                    int erv = 1;
                    OSSL_HPKE_CTX *ctx = NULL;

                    ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite,
                                            testctx, NULL);
                    if (ctx == NULL) {
                        overallresult = 0;
                    }
                    if (hpke_mode == OSSL_HPKE_MODE_PSK
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        erv = OSSL_HPKE_CTX_set1_psk(ctx, pskidp, pskp, psklen);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    }

                    if (hpke_mode == OSSL_HPKE_MODE_AUTH
                        || hpke_mode == OSSL_HPKE_MODE_PSKAUTH) {
                        erv = OSSL_HPKE_CTX_set1_auth_priv(ctx, authpriv_evp);
                        if (erv != 1) {
                            overallresult = 0;
                        }
                    }

                    erv = OSSL_HPKE_sender_seal(ctx,
                          senderpub, &senderpublen,
                          cipher, &cipherlen,
                          NULL, 0, // exporter
                          pub, publen,
                          infop, infolen,
                          aadp, aadlen,
                          plain, plainlen);
                    if (erv != 1) {
                        overallresult = 0;
                    }
#else
                    if (OSSL_HPKE_TEST_true(OSSL_HPKE_enc(testctx, NULL,
                                                          hpke_mode, hpke_suite,
                                                          pskidp, pskp, psklen,
                                                          pub, publen,
                                                          NULL, 0, authpriv_evp,
                                                          plain, plainlen,
                                                          aadp, aadlen,
                                                          infop, infolen,
                                                          seqp, seqlen,
                                                          senderpub,
                                                          &senderpublen,
                                                          cipher, &cipherlen),
                                            "OSSL_HPKE_enc") != 1) {
                        overallresult = 0;
                    }
#endif

                    memset(clear,0,clearlen);
                    if (OSSL_HPKE_TEST_true(OSSL_HPKE_dec(testctx, NULL,
                                                          hpke_mode, hpke_suite,
                                                          pskidp, pskp, psklen,
                                                          authpubp, authpublen,
                                                          NULL, 0, privp,
                                                          senderpub,
                                                          senderpublen,
                                                          cipher, cipherlen,
                                                          aadp, aadlen,
                                                          infop, infolen,
                                                          NULL, 0, //seqp, seqlen,
                                                          clear, &clearlen),
                                                "OSSL_HPKE_dec") != 1) {
                        overallresult = 0;
                    }
#ifdef NEWAPI
                    OSSL_HPKE_CTX_free(ctx);
#endif
                    EVP_PKEY_free(privp);
                    privp = NULL;
                    /* check output */
                    if (clearlen != plainlen) {
#ifdef HAPPYKEY
                        printf("clearlen!=plainlen fail\n");
#endif
                        overallresult = 0;
                    }
                    if (memcmp(clear, plain, plainlen)) {
#ifdef HAPPYKEY
                        printf("memcmp(clearlen,plainlen) fail\n");
#endif
                        overallresult = 0;
                    }
#ifdef HAPPYKEY
                    if (verbose) { printf("test success\n"); }
#endif
                    if (privp) {
                        EVP_PKEY_free(privp);
                        privp = NULL;
                    }
                }
            }
            EVP_PKEY_free(authpriv_evp);
        }
    }
    return overallresult;
}

/**
 * @brief Check mapping from strings to HPKE suites
 * @return 1 for success, other otherwise
 */
static int test_hpke_suite_strs(void)
{
    int overallresult = 1;
    int kemind = 0;
    int kdfind = 0;
    int aeadind = 0;
    int sind = 0;
    char sstr[128];
    OSSL_HPKE_SUITE stirred;

    for (kemind = 0;
         kemind != (sizeof(kem_str_list) / sizeof(char *));
         kemind++) {
        for (kdfind = 0;
             kdfind != (sizeof(kdf_str_list) / sizeof(char *));
             kdfind++) {
            for (aeadind = 0;
                 aeadind != (sizeof(aead_str_list) / sizeof(char *));
                 aeadind++) {
                snprintf(sstr,128,"%s,%s,%s",
                         kem_str_list[kemind],
                         kdf_str_list[kdfind],
                         aead_str_list[aeadind]);
                if (OSSL_HPKE_TEST_true(OSSL_HPKE_str2suite(sstr, &stirred),
                                        sstr) != 1) {
                    overallresult = 0;
                }
            }
        }
    }
    for (sind = 0;
         sind != (sizeof(bogus_suite_strs) / sizeof(char *));
         sind++) {
        char dstr[128];

        sprintf(dstr, "str2suite: %s", bogus_suite_strs[sind]);
        if (OSSL_HPKE_TEST_false(OSSL_HPKE_str2suite(bogus_suite_strs[sind],
                                                     &stirred),
                                 dstr) != 1) {
            overallresult = 0;
        }
    }
    return overallresult;
}

/**
 * @brief try the various GREASEy APIs
 * @return 1 for success, other otherwise
 */
static int test_hpke_grease(void)
{
    int overallresult = 1;
    OSSL_HPKE_SUITE g_suite;
    unsigned char g_pub[OSSL_HPKE_MAXSIZE];
    size_t g_pub_len = OSSL_HPKE_MAXSIZE;
    unsigned char g_cipher[OSSL_HPKE_MAXSIZE];
    size_t g_cipher_len = 266;
    size_t clearlen = 128;
    size_t expanded = 0;
    size_t enclen = 0;

    memset(&g_suite, 0, sizeof(OSSL_HPKE_SUITE));
    /* GREASEing */
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_good4grease(testctx, NULL, NULL, &g_suite,
                                                  g_pub, &g_pub_len, g_cipher,
                                                  g_cipher_len),
                            "good4grease") != 1) {
        overallresult = 0;
    }
    /* expansion */
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_expansion(g_suite, &enclen, clearlen, &expanded),
                            "expansion") != 1) {
        overallresult = 0;
    }
    if (expanded <= clearlen) {
#ifdef HAPPYKEY
        printf("expanded<=clearlen fail\n");
#endif
        overallresult = 0;
    }
    return overallresult;
}

/**
 * @brief try some fuzzy-ish kg, enc & dec calls
 * @return 1 for success, other otherwise
 */
static int test_hpke_badcalls(void)
{
    int overallresult = 1;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char buf1[OSSL_HPKE_MAXSIZE];
    unsigned char buf2[OSSL_HPKE_MAXSIZE];
    unsigned char buf3[OSSL_HPKE_MAXSIZE];
    unsigned char buf4[OSSL_HPKE_MAXSIZE];
    size_t aadlen = 0;
    unsigned char *aadp = NULL;
    size_t infolen = 0;
    unsigned char *infop = NULL;
    size_t seqlen = 0;
    unsigned char *seqp = NULL;
    size_t psklen = 0;
    unsigned char *pskp = NULL;
    char *pskidp = NULL;
    size_t publen = 0;
    unsigned char *pub = NULL;
    EVP_PKEY *privp = NULL;
    size_t senderpublen = 0;
    unsigned char *senderpub = NULL;
    size_t plainlen = 0;
    unsigned char *plain = NULL;
    size_t cipherlen = 0;
    unsigned char *cipher = NULL;
    size_t clearlen = 0;
    unsigned char *clear = NULL;
    size_t authpublen = 0;
    unsigned char *authpubp = NULL;
    size_t authprivlen = 0;
    unsigned char *authprivp = NULL;

    if (OSSL_HPKE_TEST_false(OSSL_HPKE_keygen(testctx, NULL,
                                              hpke_mode, hpke_suite,
                                              NULL, 0,
                                              pub, &publen,
                                              &privp),
                             "OSSL_HPKE_keygen") != 1) {
        overallresult = 0;
    }
    if (OSSL_HPKE_TEST_false(OSSL_HPKE_enc(testctx, NULL, hpke_mode, hpke_suite,
                                           pskidp, pskp, psklen,
                                           pub, publen,
                                           authprivp, authprivlen, NULL,
                                           plain, plainlen,
                                           aadp, aadlen,
                                           infop, infolen,
                                           seqp, seqlen,
                                           senderpub, &senderpublen,
                                           cipher, &cipherlen),
                             "OSSL_HPKE_enc") != 1) {
        overallresult = 0;
    }
    if (OSSL_HPKE_TEST_false(OSSL_HPKE_dec(testctx, NULL, hpke_mode, hpke_suite,
                                           pskidp, pskp, psklen,
                                           authpubp, authpublen,
                                           NULL, 0, privp,
                                           senderpub, senderpublen,
                                           cipher, cipherlen,
                                           aadp, aadlen,
                                           infop, infolen,
                                           seqp, seqlen,
                                           clear, &clearlen),
                             "OSSL_HPKE_dec") != 1) {
        overallresult = 0;
    }
    /* gen a key pair to use in enc/dec fails */
    pub = buf1;
    publen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                             hpke_mode, hpke_suite,
                                             NULL, 0,
                                             pub, &publen,
                                             &privp),
                            "OSSL_HPKE_keygen") != 1) {
        overallresult = 0;
    }
    if (OSSL_HPKE_TEST_false(OSSL_HPKE_enc(testctx, NULL, hpke_mode, hpke_suite,
                                           pskidp, pskp, psklen,
                                           pub, publen,
                                           authprivp, authprivlen, NULL,
                                           plain, plainlen,
                                           aadp, aadlen,
                                           infop, infolen,
                                           seqp, seqlen,
                                           senderpub, &senderpublen,
                                           cipher, &cipherlen),
                             "OSSL_HPKE_enc") != 1) {
        overallresult = 0;
    }

    if (overallresult != 1) {
        return overallresult;
    }
    /*
     * I'm not sure what we want below - calls like these make
     * no real sense (two output buffers at the same place in
     * memory) but I'm not sure we should prevent it.
     * Will leave this here for now in the hope of broader input.
     */
    memset(buf1, 0x01, OSSL_HPKE_MAXSIZE);
    memset(buf2, 0x02, OSSL_HPKE_MAXSIZE);
    memset(buf3, 0x03, OSSL_HPKE_MAXSIZE);
    memset(buf4, 0x04, OSSL_HPKE_MAXSIZE);
    /* same pub & priv buffers won't make for happiness */
    pub = buf1;
    publen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                             hpke_mode, hpke_suite,
                                             NULL, 0,
                                             pub, &publen,
                                             &privp),
                            "OSSL_HPKE_keygen") != 1) {
        overallresult = 0;
    }
    /* gen a usuable key pair to use in the enc/dec call below */
    pub = buf1;
    publen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_keygen(testctx, NULL,
                                                 hpke_mode, hpke_suite,
                                                 NULL, 0,
                                                 pub, &publen,
                                                 &privp),
                            "OSSL_HPKE_keygen") != 1) {
        overallresult = 0;
    }
    plain = buf3;
    plainlen = 30;
    /* cipher and senderpub as same buffer is.. silly, but "works" */
    cipher = buf4;
    cipherlen = OSSL_HPKE_MAXSIZE;
    senderpub = buf4;
    senderpublen = OSSL_HPKE_MAXSIZE;
    if (OSSL_HPKE_TEST_true(OSSL_HPKE_enc(testctx, NULL, hpke_mode, hpke_suite,
                                          pskidp, pskp, psklen,
                                          pub, publen,
                                          authprivp, authprivlen, NULL,
                                          plain, plainlen,
                                          aadp, aadlen,
                                          infop, infolen,
                                          seqp, seqlen,
                                          senderpub, &senderpublen,
                                          cipher, &cipherlen),
                            "OSSL_HPKE_enc") != 1) {
        overallresult = 0;
    }
    return overallresult;
}

# ifndef OPENSSL_NO_ASM
/*
 * NIST p256 key pair from HPKE-07 test vectors
 * FIXME: I have no idea why, but as of now building
 * with "no-asm" causes a file in a call to EC_POINT_mul
 * that's used in this test. That shows up in various
 * CI builds/tests so we'll avoid that for now by
 * just not doing that test in that case. The failure
 * is also specific to using the non-default library
 * context oddly.
 */
static unsigned char n256priv[] = {
    0x03, 0xe5, 0x2d, 0x22, 0x61, 0xcb, 0x7a, 0xc9,
    0xd6, 0x98, 0x11, 0xcd, 0xd8, 0x80, 0xee, 0xe6,
    0x27, 0xeb, 0x9c, 0x20, 0x66, 0xd0, 0xc2, 0x4c,
    0xfb, 0x33, 0xde, 0x82, 0xdb, 0xe2, 0x7c, 0xf5
};
static unsigned char n256pub[] = {
    0x04, 0x3d, 0xa1, 0x6e, 0x83, 0x49, 0x4b, 0xb3,
    0xfc, 0x81, 0x37, 0xae, 0x91, 0x71, 0x38, 0xfb,
    0x7d, 0xae, 0xbf, 0x8a, 0xfb, 0xa6, 0xce, 0x73,
    0x25, 0x47, 0x89, 0x08, 0xc6, 0x53, 0x69, 0x0b,
    0xe7, 0x0a, 0x9c, 0x9f, 0x67, 0x61, 0x06, 0xcf,
    0xb8, 0x7a, 0x5c, 0x3e, 0xdd, 0x12, 0x51, 0xc5,
    0xfa, 0xe3, 0x3a, 0x12, 0xaa, 0x2c, 0x5e, 0xb7,
    0x99, 0x14, 0x98, 0xe3, 0x45, 0xaa, 0x76, 0x60,
    0x04
};
# endif

/*
 * X25519 key pair from HPKE-07 test vectors
 */
static unsigned char x25519priv[] = {
    0x6c, 0xee, 0x2e, 0x27, 0x55, 0x79, 0x07, 0x08,
    0xa2, 0xa1, 0xbe, 0x22, 0x66, 0x78, 0x83, 0xa5,
    0xe3, 0xf9, 0xec, 0x52, 0x81, 0x04, 0x04, 0xa0,
    0xd8, 0x89, 0xa0, 0xed, 0x3e, 0x28, 0xde, 0x00
};
static unsigned char x25519pub[] = {
    0x95, 0x08, 0x97, 0xe0, 0xd3, 0x7a, 0x8b, 0xdb,
    0x0f, 0x21, 0x53, 0xed, 0xf5, 0xfa, 0x58, 0x0a,
    0x64, 0xb3, 0x99, 0xc3, 0x9f, 0xbb, 0x3d, 0x01,
    0x4f, 0x80, 0x98, 0x33, 0x52, 0xa6, 0x36, 0x17
};

/*
 * @brief test generation of pair based on private key
 * @param kem_id the KEM to use (RFC9180 code point)
 * @priv is the private key buffer
 * @privlen is the length of the private key
 * @pub is the public key buffer
 * @publen is the length of the public key
 * @return 1 for good, 0 otherwise
 *
 * This calls OSSL_HPKE_prbuf2evp without specifying the
 * public key, then extracts the public key using the
 * standard EVP_PKEY_get1_encoded_public_key API and then
 * compares that public value with the already-known public
 * value that was input.
 */
static int test_hpke_one_key_gen_from_priv(uint16_t kem_id,
                                           unsigned char *priv, size_t privlen,
                                           unsigned char *pub, size_t publen)
{
    int res = 1;
    EVP_PKEY *sk = NULL;
    unsigned char *lpub = NULL;
    size_t lpublen = 1024;

    if (OSSL_HPKE_prbuf2evp(testctx, NULL, kem_id, priv, privlen, NULL, 0, &sk)
        != 1) {
        res = 0;
    }
    if (sk == NULL) {
        res = 0;
    }
    if (res == 1) {
        lpublen = EVP_PKEY_get1_encoded_public_key(sk, &lpub);
        if (lpub == NULL || lpublen == 0) {
            res = 0;
        } else {
            if (lpublen != publen || memcmp(lpub, pub, publen)) {
                res = 0;
            }
            OPENSSL_free(lpub);
        }
    }
    EVP_PKEY_free(sk);
    return res;
}

/*
 * @brief call test_hpke_one_priv_gen for a couple of known test vectors
 * @return 1 for good, 0 otherwise
 */
static int test_hpke_gen_from_priv(void)
{
    int res = 0;

# ifndef OPENSSL_NO_ASM
    /*
     * NIST P-256 case
     * FIXME: I have no idea why, but as of now building
     * with "no-asm" causes a file in a call to EC_POINT_mul
     * that's used in this test. That shows up in various
     * CI builds/tests so we'll avoid that for now by
     * just not doing that test in that case. The failure
     * is also specific to using the non-default library
     * context oddly.
     */
    res = test_hpke_one_key_gen_from_priv(0x10,
                                          n256priv, sizeof(n256priv),
                                          n256pub, sizeof(n256pub));
    if (res != 1) { return res; }
# endif

    /* X25519 case */
    res = test_hpke_one_key_gen_from_priv(0x20,
                                          x25519priv, sizeof(x25519priv),
                                          x25519pub, sizeof(x25519pub));
    if (res != 1) { return res; }

    return res;
}

/* from RFC 9180 Appendix A.1.1 */
static unsigned char ikm25519[] = {
    0x72, 0x68, 0x60, 0x0d, 0x40, 0x3f, 0xce, 0x43,
    0x15, 0x61, 0xae, 0xf5, 0x83, 0xee, 0x16, 0x13,
    0x52, 0x7c, 0xff, 0x65, 0x5c, 0x13, 0x43, 0xf2,
    0x98, 0x12, 0xe6, 0x67, 0x06, 0xdf, 0x32, 0x34
};
static unsigned char pub25519[] = {
    0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
    0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
    0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
    0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31
};

/* from RFC9180 Appendix A.3.1 */
static unsigned char ikmp256[] = {
    0x42, 0x70, 0xe5, 0x4f, 0xfd, 0x08, 0xd7, 0x9d,
    0x59, 0x28, 0x02, 0x0a, 0xf4, 0x68, 0x6d, 0x8f,
    0x6b, 0x7d, 0x35, 0xdb, 0xe4, 0x70, 0x26, 0x5f,
    0x1f, 0x5a, 0xa2, 0x28, 0x16, 0xce, 0x86, 0x0e
};
static unsigned char pubp256[] = {
    0x04, 0xa9, 0x27, 0x19, 0xc6, 0x19, 0x5d, 0x50,
    0x85, 0x10, 0x4f, 0x46, 0x9a, 0x8b, 0x98, 0x14,
    0xd5, 0x83, 0x8f, 0xf7, 0x2b, 0x60, 0x50, 0x1e,
    0x2c, 0x44, 0x66, 0xe5, 0xe6, 0x7b, 0x32, 0x5a,
    0xc9, 0x85, 0x36, 0xd7, 0xb6, 0x1a, 0x1a, 0xf4,
    0xb7, 0x8e, 0x5b, 0x7f, 0x95, 0x1c, 0x09, 0x00,
    0xbe, 0x86, 0x3c, 0x40, 0x3c, 0xe6, 0x5c, 0x9b,
    0xfc, 0xb9, 0x38, 0x26, 0x57, 0x22, 0x2d, 0x18,
    0xc4
};

/*
 * A test vector that exercises the counter iteration
 * for p256. This was contributed by Ilari L. on the
 * CFRG list, see the mail archive:
 * https://mailarchive.ietf.org/arch/msg/cfrg/4zwl_y5YN6OU9oeWZOMHNOlOa2w/
 */
static unsigned char ikmiter[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x38, 0xb5, 0xec
};
static unsigned char pubiter[] = {
    0x04, 0x7d, 0x0c, 0x87, 0xff, 0xd5, 0xd1, 0x45,
    0x54, 0xa7, 0x51, 0xdf, 0xa3, 0x99, 0x26, 0xa9,
    0xe3, 0x0e, 0x7c, 0x3c, 0x65, 0x62, 0x4f, 0x4b,
    0x5f, 0xb3, 0xad, 0x7a, 0xa4, 0xda, 0xc2, 0x4a,
    0xd8, 0xf5, 0xbe, 0xd0, 0xe8, 0x6e, 0xb8, 0x84,
    0x1c, 0xe4, 0x89, 0x2e, 0x0f, 0xc3, 0x87, 0xbb,
    0xdb, 0xfe, 0x16, 0x0d, 0x58, 0x9c, 0x89, 0x2d,
    0xd4, 0xb1, 0x46, 0x4a, 0xc3, 0x51, 0xc5, 0x6f,
    0xb6
};

/* from RFC9180 Appendix A.6.1 */
static unsigned char ikmp521[] = {
    0x7f, 0x06, 0xab, 0x82, 0x15, 0x10, 0x5f, 0xc4,
    0x6a, 0xce, 0xeb, 0x2e, 0x3d, 0xc5, 0x02, 0x8b,
    0x44, 0x36, 0x4f, 0x96, 0x04, 0x26, 0xeb, 0x0d,
    0x8e, 0x40, 0x26, 0xc2, 0xf8, 0xb5, 0xd7, 0xe7,
    0xa9, 0x86, 0x68, 0x8f, 0x15, 0x91, 0xab, 0xf5,
    0xab, 0x75, 0x3c, 0x35, 0x7a, 0x5d, 0x6f, 0x04,
    0x40, 0x41, 0x4b, 0x4e, 0xd4, 0xed, 0xe7, 0x13,
    0x17, 0x77, 0x2a, 0xc9, 0x8d, 0x92, 0x39, 0xf7,
    0x09, 0x04
};
static unsigned char pubp521[] = {
    0x04, 0x01, 0x38, 0xb3, 0x85, 0xca, 0x16, 0xbb,
    0x0d, 0x5f, 0xa0, 0xc0, 0x66, 0x5f, 0xbb, 0xd7,
    0xe6, 0x9e, 0x3e, 0xe2, 0x9f, 0x63, 0x99, 0x1d,
    0x3e, 0x9b, 0x5f, 0xa7, 0x40, 0xaa, 0xb8, 0x90,
    0x0a, 0xae, 0xed, 0x46, 0xed, 0x73, 0xa4, 0x90,
    0x55, 0x75, 0x84, 0x25, 0xa0, 0xce, 0x36, 0x50,
    0x7c, 0x54, 0xb2, 0x9c, 0xc5, 0xb8, 0x5a, 0x5c,
    0xee, 0x6b, 0xae, 0x0c, 0xf1, 0xc2, 0x1f, 0x27,
    0x31, 0xec, 0xe2, 0x01, 0x3d, 0xc3, 0xfb, 0x7c,
    0x8d, 0x21, 0x65, 0x4b, 0xb1, 0x61, 0xb4, 0x63,
    0x96, 0x2c, 0xa1, 0x9e, 0x8c, 0x65, 0x4f, 0xf2,
    0x4c, 0x94, 0xdd, 0x28, 0x98, 0xde, 0x12, 0x05,
    0x1f, 0x1e, 0xd0, 0x69, 0x22, 0x37, 0xfb, 0x02,
    0xb2, 0xf8, 0xd1, 0xdc, 0x1c, 0x73, 0xe9, 0xb3,
    0x66, 0xb5, 0x29, 0xeb, 0x43, 0x6e, 0x98, 0xa9,
    0x96, 0xee, 0x52, 0x2a, 0xef, 0x86, 0x3d, 0xd5,
    0x73, 0x9d, 0x2f, 0x29, 0xb0
};

/*
 * @brief generate a key pair from an initial string and check public
 * @param kem_id the KEM to use (RFC9180 code point)
 * @ikm is the initial key material buffer
 * @ikmlen is the length of ikm
 * @pub is the public key buffer
 * @publen is the length of the public key
 * @return 1 for good, other otherwise
 *
 * This calls OSSL_HPKE_keygen specifying only the IKM, then
 * compares the key pair values with the already-known values
 * that were input.
 */
static int test_hpke_one_ikm_gen(uint16_t kem_id,
                                 unsigned char *ikm, size_t ikmlen,
                                 unsigned char *pub, size_t publen)
{
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    unsigned char lpub[OSSL_HPKE_MAXSIZE];
    size_t lpublen = OSSL_HPKE_MAXSIZE;
    EVP_PKEY *sk = NULL;

    hpke_suite.kem_id = kem_id;
    if (OSSL_HPKE_keygen(testctx, NULL, hpke_mode, hpke_suite,
                         ikm, ikmlen, lpub, &lpublen, &sk) != 1) {
        return - __LINE__;
    }
    if (sk == NULL)
        return - __LINE__;
    EVP_PKEY_free(sk);
    if (lpublen != publen)
        return - __LINE__;
    if (memcmp(pub, lpub, publen))
        return - __LINE__;

    return 1;
}

static int test_hpke_ikms(void)
{
    int res = 1;

    res = test_hpke_one_ikm_gen(0x20,
                                ikm25519, sizeof(ikm25519),
                                pub25519, sizeof(pub25519));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(0x12,
                                ikmp521, sizeof(ikmp521),
                                pubp521, sizeof(pubp521));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(0x10,
                                ikmp256, sizeof(ikmp256),
                                pubp256, sizeof(pubp256));
    if (res != 1)
        return res;

    res = test_hpke_one_ikm_gen(0x10,
                                ikmiter, sizeof(ikmiter),
                                pubiter, sizeof(pubiter));
    if (res != 1)
        return res;

    return res;
}

static int test_hpke_exporters(void)
{
    int res = 1;
    unsigned char exportval[OSSL_HPKE_MAXSIZE];
    size_t exportval_len = OSSL_HPKE_MAXSIZE;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    char *tstr="test";

#ifdef TBD
    res = OSSL_HPKE_export(testctx, NULL, suite,
                           (unsigned char *)tstr, strlen(tstr), 240,
                           exportval, &exportval_len);
    if (res != 1)
        return res;
#endif

    return res;
}

static int test_hpke(void)
{
    int res = 1;

    res = test_hpke_modes_suites();
    if (res != 1)
        return res;

    res = test_hpke_suite_strs();
    if (res != 1)
        return res;

    res = test_hpke_grease();
    if (res != 1)
        return res;

    res = test_hpke_badcalls();
    if (res != 1)
        return res;

    res = test_hpke_gen_from_priv();
    if (res != 1)
        return res;

    res = test_hpke_ikms();
    if (res != 1)
        return res;

    res = test_hpke_exporters();
    if (res != 1)
        return res;

    return res;
}
#ifdef HAPPYKEY
/*
 * @brief hey it's main()
 */
int main(int argc, char **argv)
{
    int apires = 1;
    int opt;

    while ((opt = getopt(argc, argv, "?hv")) != -1) {
        switch (opt) {
        case '?':
            usage(argv[0], "Unexpected option");
            break;
        case 'v':
            verbose++;
            break;
        default:
            usage(argv[0], "unknown arg");
        }
    }

    /*
     * Init OpenSSL stuff - copied from lighttpd
     */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
                        OPENSSL_INIT_ADD_ALL_DIGESTS |
                        OPENSSL_INIT_LOAD_CONFIG, NULL);

    apires = test_hpke();
    if (apires == 1) {
        printf("API test success\n");
    } else {
        printf("API test fail (%d)\n", apires);
    }
    return apires;
}
#endif
