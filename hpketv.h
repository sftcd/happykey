/*
 * Copyright 2019 Stephen Farrell. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file 
 * Stuff related to test vectors for HPKE.
 *
 * This is compiled in if TESTVECTORS is #define'd, otherwise not.
 *
 * The overall plan with test vectors is to:
 * - define data structures here to store the test vectors 
 * - have global variables with the actual data
 * - have a #ifdef'd command line argument to generate/check a test vector
 * - have #ifdef'd additional parameters to _enc/_dec functions for doing
 *   generation/checking 
 *
 * Source for test vectors is:
 * https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json
 * A copy from 20191126 is are also in this repo in test-vectors.json
 *
 */

#ifndef HPKETV_H_INCLUDED
#define HPKETV_H_INCLUDED

#ifdef TESTVECTORS

typedef struct hpke_tv_encs_s {
    const char *aad;
    const char *plaintext;
    const char *ciphertext;
} hpke_tv_encs_t;

typedef struct hpke_tv_s {
    uint8_t mode;
    uint16_t kdfID;
    uint16_t aeadID;
    uint16_t kemID;
    const char *context;
    const char *skI;
    const char *pkI;
    const char *zz;
    const char *secret;
    const char *enc;
    const char *info;
    const char *pskID;
    const char *nonce;
    const char *key;
    const char *pkR;
    const char *pkE;
    const char *skR;
    const char *skE;
    const char *psk;
    int nencs;
    hpke_tv_encs_t *encs;
    void *jobj; 
} hpke_tv_t;

/*
 * @brief load test vectors from json file to array
 * @param filename is the json file
 * @param nelems returns with the number of array elements
 * @param array returns with the elements
 * @return 1 for good, other for bad
 */
int hpke_tv_load(char *fname, int *nelems, hpke_tv_t **array);

/*
 * @brief free up test vector array
 * @param array is a guess what?
 * @return 1 for good, other for bad
 *
 * Caller should free "parent" array
 */
int hpke_tv_free(hpke_tv_t *array);

/*
 * @brief select a test vector to use based on mode and suite
 * @param nelems is the number of array elements
 * @param array is the elements
 * @param selector is a string to use
 * @param tv is the chosen test vector (doesn't need to be freed)
 * @return 1 for good, other for bad
 *
 * This function will randomly pick a matching test vector
 * that matches the specified criteria.
 *
 * The string to use is like "0,1,1,2" specifying the 
 * mode and suite in the (sorta:-) obvious manner.
 */
int hpke_tv_pick(int nelems, hpke_tv_t *arr, char *selector, hpke_tv_t *tv);

#endif // TESTVECTORS

#endif // HPKETV_H_INCLUDED

