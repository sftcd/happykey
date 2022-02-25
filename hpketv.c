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
 * The latest copy from that repo is also in this repo in test-vectors.json
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
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


#ifndef HPKE_A2B
/*!
 * @brief  Map ascii to binary - utility macro used in >1 place
 */
#define HPKE_A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
                        (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))
#endif

/*
 * Marcros to grab a numeric or string field from json-c object 
 * and whack in same-named field of ours
 */
/*!
 * @brief copy typed/named field from json-c to hpke_tv_t
 */
#define grabnum(_xx)  if (!strcmp(key,""#_xx"")) { thearr[i]._xx=json_object_get_int(val); } 

/*!
 * @brief copy typed/named field from json-c to hpke_tv_t
 */
#define grabstr(_xx)  if (!strcmp(key,""#_xx"")) { thearr[i]._xx=json_object_get_string(val); }

/*!
 * @brief copy typed/named field from json-c to hpke_tv_t
 */
#define grabestr(_xx)  if (!strcmp(key1,""#_xx"")) { encs[j]._xx=json_object_get_string(val1); }

/*!
 * @brief print the name of a field and the value of that field
 */
#define PRINTIT(_xx) printf("\t"#_xx": %s\n",a->_xx);


/*
 * @brief go from uncompressed to compressed NIST curve public key
 * @param uncomp is the ascii-hex uncompressed point
 * @return is the uppercase ascii-hex for the compressed point
 */
static char *u2c_transform(const char *uncomp)
{
    size_t pklen=(strlen(uncomp)-2)/4;
    char *pnew=malloc(2*pklen+2+1);
    memset(pnew,0,2*pklen+2+1);
    memcpy(pnew,uncomp,2*pklen+2);
    pnew[0]='0'; 
    char last=uncomp[strlen(uncomp)-1];
    if (HPKE_A2B(last)%2) {
        pnew[1]='3';
    } else {
        pnew[1]='2';
    }
    for (int i=0;i!=strlen(pnew);i++) {
        pnew[i]=toupper(pnew[i]);
    }
    return(pnew);
}

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
    size_t mssize=10*640*1024; // 10 microsoft units 
    mystring=malloc(mssize+1); // one more for a definite end of string NUL
    memset(mystring,0,mssize+1);
    int stringlen = 0;
    enum json_tokener_error jerr;
    do {
        if (!feof(fp)) {
            fread(mystring,mssize,1,fp);
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
            grabnum(kdf_id)
            grabnum(aead_id)
            grabnum(kem_id)

            grabstr(info)
            grabstr(exporter_secret)
            grabstr(enc)
            grabstr(key_schedule_context)
            grabstr(nonce)
            grabstr(secret)
            grabstr(shared_secret)
            grabstr(skEm)
            grabstr(skRm)
            grabstr(skSm)
            grabstr(pkEm)
            grabstr(pkRm)
            grabstr(pkSm)
            grabstr(seedE)
            grabstr(seedR)
            grabstr(seedS)
            grabstr(psk_id)
            grabstr(psk)

            if (!strcmp(key,"encryptions")) {
                for (j = 0; j < json_object_array_length(val); j++) {
                    encs=realloc(encs,(j+1)*sizeof(hpke_tv_encs_t));
                    memset(&encs[j],0,sizeof(hpke_tv_encs_t));
                    json_object *tmp1 = json_object_array_get_idx(val, j);
                    json_object_object_foreach(tmp1, key1, val1) {
                        grabestr(aad)
                        grabestr(nonce)
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

#if 0
    /* 
     * We may need special handling for NIST curve values as 
     * stored in test vectors if cmopressed form ends up being
     * really used. So keep this code for a bit.
     */
    for (i=0;i!=*nelems;i++) {
        if (thearr[i].kem_id==0x01) {
            /* we don't really want uncompressed points */
            /* this is utterly messing about ... */
            if (thearr[i].pkRm) {
                thearr[i].pkRm=u2c_transform(thearr[i].pkRm);
            }
            if (thearr[1].pkI) {
                thearr[i].pkI=u2c_transform(thearr[i].pkI);
            }
            if (thearr[1].pkE) {
                thearr[i].pkE=u2c_transform(thearr[i].pkE);
            }
        }
    }
#endif

    return(1);
}


/*
 * @brief free up test vector array
 * @param nelems is the number of array elements
 * @param array is a guess what?
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
        printf("Test Vector Element %d of %d\n",i+1,nelems);
        printf("\tmode: %d, kem: %d, kdf: %d, aead: %d\n",a->mode,a->kem_id,a->kdf_id,a->aead_id);


        PRINTIT(info)
        PRINTIT(exporter_secret)
        PRINTIT(enc)
        PRINTIT(key_schedule_context)
        PRINTIT(nonce)
        PRINTIT(secret)
        PRINTIT(shared_secret)
        PRINTIT(skEm)
        PRINTIT(skRm)
        PRINTIT(skSm)
        PRINTIT(pkEm)
        PRINTIT(pkRm)
        PRINTIT(pkSm)
        PRINTIT(seedE)
        PRINTIT(seedR)
        PRINTIT(psk_id)
        PRINTIT(psk)
        if (a->encs) {
            printf("\taad: %s\n",a->encs[0].aad);
            printf("\tnonce: %s\n",a->encs[0].nonce);
            printf("\tplaintext: %s\n",a->encs[0].plaintext);
            printf("\tciphertext: %s\n",a->encs[0].ciphertext);
        }

        a++;
    }
    return;
}


/* 
 * @brief check if test vector matches mode/suite
 * @param mode is the selected mode
 * @param suite is the ciphersuite
 * @param a is a test vector
 * @return 1 for match zero otherwise
 *
 * For now, this just matches the first <mode>,default-suite
 * test vector.
 */
static int hpke_tv_match(unsigned int mode, hpke_suite_t suite,hpke_tv_t *a)
{
    if (a && a->mode==mode &&
        a->kdf_id==suite.kdf_id && 
        a->kem_id==suite.kem_id && 
        a->aead_id==suite.aead_id ) return(1);
    return(0);
}

/*
 * @brief select a test vector to use based on mode and suite
 * @param mode is the selected mode
 * @param suite is the ciphersuite
 * @param nelems is the number of array elements
 * @param array is the elements
 * @param tv is the chosen test vector (doesn't need to be freed)
 * @return 1 for good, other for bad
 *
 * This function will pick the first matching test vector
 * that matches the specified criteria. 
 *
 * It looks (so far) like there's only one match for each of
 * mode=base/psk for my default ciphersuite. So no point in 
 * spending time now on randomly picking;-)
 */
int hpke_tv_pick(unsigned int mode, hpke_suite_t suite, int nelems, hpke_tv_t *arr,hpke_tv_t **tv)
{
    hpke_tv_t *a=arr;
    hpke_tv_t **resarr=NULL; ///< array of pointers to matching vectors
    resarr=malloc(nelems*sizeof(hpke_tv_t*));
    if (!resarr) return(__LINE__);
    memset(resarr,0,nelems*sizeof(hpke_tv_t*));
    int mind=0;
    int gotmatch=0;
    int lastmatch=-1;
    int i=0;
    for (i=0;i!=nelems;i++) {
        if (hpke_tv_match(mode,suite,a)) {
            resarr[mind++]=a;
            gotmatch=1;
            lastmatch=i;
        }
        a++;
    }
    if (!gotmatch) {
        free(resarr);
        return(0);
    }
    /*
     * We expect exactly one match but just in case...
     */
    if (mind==1) {
        *tv=resarr[0];
        free(resarr);
        return(1);
    }
    *tv=resarr[0];
    free(resarr);
    printf("Got %d matches, last at %d, taking 1st\n",mind,lastmatch);
    return(1);
}

