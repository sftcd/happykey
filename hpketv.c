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
 * Implementation related to test vectors for HPKE.
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

#ifndef TESTVECTORS
/*!
 * Crap out if this isn't defined.
 */
#define FAIL2BUILD(x) int x;
FAIL2BUILD("Don't build hpkeyv.c without TESTVECRTORS being defined")
#endif

/*!
 * @brief load test vectors from json file to array
 * @param fname is the json file
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
    char *mystring;
    mystring=malloc(640*1024);
    int stringlen = 0;
    enum json_tokener_error jerr;
    do {
        if (!feof(fp)) {
            memset(mystring,0,640*1024);
            fread(mystring,640*1024,1,fp);
        } else {
            fprintf(stderr, "Error: reached EOF of %s before json decode done - exiting\n",fname);
            return(__LINE__);
        }
        stringlen = strlen(mystring);
        jobj = json_tokener_parse_ex(tok, mystring, stringlen);
    } while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);
    free(mystring);
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

/*
 * Marcros to grab a numeric or string field from json-c object 
 * and whack in same-named field of ours
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
 * @param nelems is the number of array elements
 * @param array is a guess what?
 * @return 1 for good, other for bad
 *
 * Caller doesn't need to free "parent" array
 */
void hpke_tv_free(int nelems, hpke_tv_t *array)
{
    if (!array) return;
    json_object *jobj=(json_object*)array[0].jobj;
    for (int i=0;i!=nelems;i++) {
       if (array[i].encs) free(array[i].encs); 
    }
    free(array);
    json_object_put(jobj);
    return;
}

/*!
 * @brief print the name of a field and the value of that field
 */
#define PRINTIT(_xx) printf("\t"#_xx": %s\n",a->_xx);

/*
 * @brief print test vectors
 * @param nelems is the number of array elements
 * @param array is the elements
 * @return 1 for good, other for bad
 */
void hpke_tv_print(int nelems, hpke_tv_t *array)
{
    hpke_tv_t *a=array;
    if (!array) return;
    for (int i=0;i!=nelems;i++) {
        printf("Test Vector Element %d\n",i);
        printf("\tmode: %d, suite: %d,%d,%d\n",a->mode,a->kdfID,a->kemID,a->aeadID);
        PRINTIT(pkR);
        PRINTIT(context);
        PRINTIT(skI)
        PRINTIT(pkI)
        PRINTIT(zz)
        PRINTIT(secret)
        PRINTIT(enc)
        PRINTIT(info)
        PRINTIT(pskID)
        PRINTIT(nonce)
        PRINTIT(key)
        PRINTIT(pkR)
        PRINTIT(pkE)
        PRINTIT(skR)
        PRINTIT(skE)
        PRINTIT(psk)
        if (a->encs) {
            printf("\taad: %s\n",a->encs[0].aad);
            printf("\tplaintext: %s\n",a->encs[0].plaintext);
            printf("\tciphertext: %s\n",a->encs[0].ciphertext);
        }

        a++;
    }
    return;
}


/* 
 * @brief check if test vector matches selector
 * @param a is a test vector
 * @param is a selector (currently unused)
 * @return 1 for match zero otherwise
 *
 * For now, this just matches the first base,default-suite
 * test vecctor.
 */
static int hpke_tv_match(hpke_tv_t *a, char *selector)
{
    if (a && a->mode==HPKE_MODE_BASE &&
        a->kdfID==HPKE_KDF_ID_HKDF_SHA256 &&
        a->kemID==HPKE_KEM_ID_25519 &&
        a->aeadID==HPKE_AEAD_ID_AES_GCM_128) return(1);
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
 * This function will pick the first matching test vector
 * that matches the specified criteria. 
 *
 * TODO: Change to random later, when stuff works.
 *
 * The string to use is like "0,1,1,2" specifying the 
 * mode and suite in the (sorta:-) obvious manner.
 */
int hpke_tv_pick(int nelems, hpke_tv_t *arr, char *selector, hpke_tv_t **tv)
{
    hpke_tv_t *a=arr;
    for (int i=0;i!=nelems;i++) {
        if (hpke_tv_match(a,selector)) {
            *tv=a;
            return(1);
        }
        a++;
    }
    return(0);
}

