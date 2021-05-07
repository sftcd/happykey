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
 * A couple of tests making EVP_PKEY's from pub/priv for NIST and non-NIST algs
 * Took a while, and some help, to figure out which flavour of what to put 
 * where.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

int bufs2evp(
        const char *keytype,
        char *groupname,
        unsigned char *privbuf, size_t privbuflen,
        unsigned char *pubuf, size_t pubuflen,
        EVP_PKEY **pkey)
{

    int erv=1;
    EVP_PKEY_CTX *ctx=NULL;
    BIGNUM *priv=NULL;
    OSSL_PARAM_BLD *param_bld=NULL;;
    OSSL_PARAM *params = NULL;

    if (!keytype) return(0);

    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
        erv=__LINE__; goto err; 
    }
    if (groupname!=NULL && OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", groupname,0)!=1) {
        erv=__LINE__; goto err; 
    }
    if (pubuf && pubuflen>0) {
        if (OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", pubuf, pubuflen)!=1) {
            erv=__LINE__; goto err; 
        }
    } 
    if (strlen(keytype)==2 && !strcmp(keytype,"EC")) {
        priv = BN_bin2bn(privbuf, privbuflen, NULL);
        if (!priv) {
            erv=__LINE__; goto err; 
        } 
        if (OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv)!=1) {
            erv=__LINE__; goto err; 
        }
    } else {
        if (OSSL_PARAM_BLD_push_octet_string(param_bld, "priv", privbuf, privbuflen)!=1) {
            erv=__LINE__; goto err; 
        }
    }

    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params) {
        erv=__LINE__; goto err; 
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL,keytype, NULL);
    if (ctx == NULL) {
        erv=__LINE__; goto err; 
    }
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        erv=__LINE__; goto err; 
    } 
    if (EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        erv=__LINE__; goto err; 
    } 
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    if (priv) BN_free(priv);
    return 1;
err:
    if (priv) BN_free(priv);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (params) OSSL_PARAM_free(params);
    return erv;
}

/*!
 * @brief  Map ascii to binary - utility macro used in >1 place 
 */
#define HPKE_A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
                        (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))

/*!
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good otherwise bad
 */
int ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf)
{
    size_t lblen=0;
    unsigned char *lbuf=NULL;
    if (ahlen <=0 || ah==NULL || blen==NULL || buf==NULL) {
        return 0;
    }
    if (ahlen%1) {
        return 0;
    }
    lblen=ahlen/2;
    lbuf=OPENSSL_malloc(lblen);
    if (lbuf==NULL) {
        return 0;
    }
    int i=0;
    for (i=0;i!=lblen;i++) {
        lbuf[i]=HPKE_A2B(ah[2*i])*16+HPKE_A2B(ah[2*i+1]);
    }
    *blen=lblen;
    *buf=lbuf;
    return 1;
}

/*
 * NIST p256 key pair from HPKE-07 test vectors
 */
const char *nprivstr="03e52d2261cb7ac9d69811cdd880eee627eb9c2066d0c24cfb33de82dbe27cf5";
const char *npubstr="043da16e83494bb3fc8137ae917138fb7daebf8afba6ce7325478908c653690be70a9c9f676106cfb87a5c3edd1251c5fae33a12aa2c5eb7991498e345aa766004";

/*
 * X25519 key pair from HPKE-07 test vectors
 */
const char *xprivstr="6cee2e2755790708a2a1be22667883a5e3f9ec52810404a0d889a0ed3e28de00";
const char *xpubstr="950897e0d37a8bdb0f2153edf5fa580a64b399c39fbb3d014f80983352a63617";

int main(int argc, char **argv) 
{

    int rv=0;
    EVP_PKEY *retkey=NULL;
    unsigned char *nprivbuf; size_t nprivlen=0;
    unsigned char *npubbuf; size_t npublen=0;
    unsigned char *xprivbuf; size_t xprivlen=0;
    unsigned char *xpubbuf; size_t xpublen=0;

    ah_decode(strlen(nprivstr),nprivstr,&nprivlen,&nprivbuf);
    ah_decode(strlen(npubstr),npubstr,&npublen,&npubbuf);
    ah_decode(strlen(xprivstr),xprivstr,&xprivlen,&xprivbuf);
    ah_decode(strlen(xpubstr),xpubstr,&xpublen,&xpubbuf);

    /* 
     * First do p-256 then x25519 
     */

    rv=bufs2evp("EC","P-256",nprivbuf,nprivlen,npubbuf,npublen,&retkey);
    if (rv==1) {
        printf("P-256 with key pair worked\n");
    } else {
        printf("P-256 with key pair failed at %d\n",rv);
    }
    EVP_PKEY_free(retkey);retkey=NULL;

    rv=bufs2evp("EC","P-256",nprivbuf,nprivlen,NULL,0,&retkey);
    if (rv==1) {
        printf("P-256 with just private key worked\n");
    } else {
        printf("P-256 with key pair failed at %d\n",rv);
    }
    EVP_PKEY_free(retkey);retkey=NULL;

    rv=bufs2evp("X25519",NULL,xprivbuf,xprivlen,xpubbuf,xpublen,&retkey);
    if (rv==1) {
        printf("X25519 with key pair worked\n");
    } else {
        printf("X25519 with key pair failed at %d\n",rv);
    }
    EVP_PKEY_free(retkey);retkey=NULL;

    rv=bufs2evp("X25519",NULL,xprivbuf,xprivlen,NULL,0,&retkey);
    if (rv==1) {
        printf("X25519 with just private key worked\n");
    } else {
        printf("X25519 with just private key failed at %d\n",rv);
    }
    EVP_PKEY_free(retkey);retkey=NULL;

    OPENSSL_free(npubbuf); OPENSSL_free(xpubbuf);
    OPENSSL_free(nprivbuf); OPENSSL_free(xprivbuf);

    return 1;
}
