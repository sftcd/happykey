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

#ifdef TESTVECTORS

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hpke.h"
#include "hpketv.h"

/*
 * @brief load test vectors from json file to array
 * @param filename is the json file
 * @param nelems returns with the number of array elements
 * @param array returns with the elements
 * @return 1 for good, other for bad
 */
int hpke_tv_load(char *fname, int *nelems, hpke_tv_t **array)
{
    return(0);
}


/*
 * @brief free up test vector array
 * @param array is a guess what?
 * @return 1 for good, other for bad
 *
 * Caller should free "parent" array
 */
int hpke_tv_free(hpke_tv_t *array)
{
    return(0);
}


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
int hpke_tv_pick(int nelems, hpke_tv_t *arr, char *selector, hpke_tv_t *tv)
{
    return(0);
}

#endif
