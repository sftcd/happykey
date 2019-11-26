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
/*
 * Since this is only used for test vectors and hence
 * from the command line, we don't need to care about
 * portability so much and will use e.g. fprintf(stderr,"...
 * as convenient.
 */
#include <stdio.h>

#include "hpke.h"
#include "hpketv.h"

#include <json.h>
#include <json_tokener.h>

/*
 * @brief load test vectors from json file to array
 * @param filename is the json file
 * @param nelems returns with the number of array elements
 * @param array returns with the elements
 * @return 1 for good, other for bad
 */
int hpke_tv_load(char *fname, int *nelems, hpke_tv_t **array)
{
    FILE *fp=fopen(fname,"r");
    if (fp==NULL) {
        fprintf(stderr,"Can't open test vector file %s - exiting\n",fname);
        return(__LINE__);
    }
    /*
     * We'll try read that file and decode it into a json object
     * following http://json-c.github.io/json-c/json-c-0.13.1/doc/html/json__tokener_8h.html#a236ef64d079822a4411d13eae7190c4d
     */
    struct json_tokener* tok=json_tokener_new();
    json_object *jobj = NULL;
    char mystring[1025];
    int stringlen = 0;
    enum json_tokener_error jerr;
    do {
        memset(mystring,0,1025);
        if (!feof(fp)) {
            fread(mystring,1024,1,fp);
        } else {
            fprintf(stderr, "Error: reached EOF of %s before json decode done - exiting\n",fname);
            return(__LINE__);
        }
        stringlen = strlen(mystring);
        jobj = json_tokener_parse_ex(tok, mystring, stringlen);
    } while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);
    if (jerr != json_tokener_success) {
        fprintf(stderr, "Error: %s\n", json_tokener_error_desc(jerr));
        // Handle errors, as appropriate for your application.
        return(__LINE__);
    }
    json_tokener_free(tok);
    fclose(fp);
    /* 
     * Iterate over the JSON object array filling in stuctures each time
     * We need to delve one level down once for each instance for the
     * ciphertexts.
     *
     * Again, since this code will be compiled out, we're loosey-goosey
     * with error handling.
     */

#define grabnum(_xx)  if (!strcmp(key,""#_xx"")) { \
                        thearr[i]._xx=json_object_get_int(val); \
                      }
#define grabstr(_xx)  if (!strcmp(key,""#_xx"")) { \
                        thearr[i]._xx=json_object_get_string(val); \
                      }
#define grabestr(_xx)  if (!strcmp(key1,""#_xx"")) { \
                        encs[j]._xx=json_object_get_string(val1); \
                      }

    hpke_tv_t *thearr=NULL;
    int i,j;
	for (i = 0; i < json_object_array_length(jobj); i++) {
        hpke_tv_encs_t *encs=NULL;
        thearr=realloc(thearr,(i+1)*sizeof(hpke_tv_t));
        memset(&thearr[i],0,sizeof(hpke_tv_t));
        thearr[i].jobj=(void*)jobj;
		json_object *tmp = json_object_array_get_idx(jobj, i);
        json_object_object_foreach(tmp, key, val) {
            grabnum(mode)
            grabnum(kdfID)
            grabnum(aeadID)
            grabnum(kemID)
            grabstr(context)
            grabstr(skI)
            grabstr(pkI)
            grabstr(zz)
            grabstr(secret)
            grabstr(enc)
            grabstr(info)
            grabstr(pskID)
            grabstr(nonce)
            grabstr(key)
            grabstr(pkR)
            grabstr(pkE)
            grabstr(skR)
            grabstr(skE)
            grabstr(psk)
            if (!strcmp(key,"encryptions")) {
	            for (j = 0; j < json_object_array_length(val); j++) {
                    encs=realloc(encs,(j+1)*sizeof(hpke_tv_encs_t));
                    memset(&encs[j],0,sizeof(hpke_tv_encs_t));
		            json_object *tmp1 = json_object_array_get_idx(val, j);
                    json_object_object_foreach(tmp1, key1, val1) {
                        grabestr(aad)
                        grabestr(plaintext)
                        grabestr(ciphertext)
                    }
                }
                thearr[i].nencs=j;
                thearr[i].encs=encs;
                encs=NULL;
            }

        }
    }

    *nelems=i;
    *array=thearr;
    return(1);
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
