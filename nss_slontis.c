/*
 * Copyright 2022 Stephen Farrell. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file
 *
 * A round-trip test using NSS to encrypt and slontis to decrypt.
 *
 */

/*
 * Openssl includes
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
#include <openssl/hpke.h>

#define MEMCHAR 0xfa

/*
 * Our wrapper for NSS stuff - implemented in neod_nss.c
 */
extern int nss_enc(
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t *enclen, unsigned char *enc,
        size_t *cipherlen, unsigned char *cipher
        );

/*!
 * @brief for odd/occasional debugging
 *
 * @param fout is a FILE * to use
 * @param msg is prepended to print
 * @param buf is the buffer to print
 * @param blen is the length of the buffer
 * @return 1 for success 
 */
static int neod_pbuf(char *msg,unsigned char *buf,size_t blen) 
{
    if (!msg) {
        printf("NULL msg:");
    } else {
        printf("%s (%lu): ",msg,blen);
    }
    if (!buf) {
        printf("buf is NULL, so probably something wrong\n");
        return 1;
    }
    if (blen==0) {
        printf("length is 0, so probably something wrong\n");
        return 1;
    }
    size_t i=0;
    for (i=0;i<blen;i++) {
        printf("%02x",buf[i]);
    }
    printf("\n");
    return 1;
}

#define OSSL_HPKE_MAXSIZE 1536

int main(int argc, char **argv) 
{
    size_t publen=0; unsigned char *pub=NULL;
    EVP_PKEY *privevp=NULL;
    EVP_PKEY *pubevp=NULL;
    OSSL_HPKE_KEM *kem=NULL;
    int rv;
    size_t aadlen=OSSL_HPKE_MAXSIZE; unsigned char aad[OSSL_HPKE_MAXSIZE];
    size_t infolen=OSSL_HPKE_MAXSIZE; unsigned char info[OSSL_HPKE_MAXSIZE];
    size_t cipherlen=OSSL_HPKE_MAXSIZE; unsigned char cipher[OSSL_HPKE_MAXSIZE];
    size_t enclen=OSSL_HPKE_MAXSIZE; unsigned char enc[OSSL_HPKE_MAXSIZE];
    size_t psklen=0; unsigned char *psk=NULL; char *pskid=NULL;
    size_t clearlen=OSSL_HPKE_MAXSIZE; unsigned char clear[OSSL_HPKE_MAXSIZE];
    size_t recclearlen=OSSL_HPKE_MAXSIZE; unsigned char recclear[OSSL_HPKE_MAXSIZE];

    /* Generate a key pair */
    kem=OSSL_HPKE_KEM_new("X25519",NULL,"HKDF","SHA256");
    OSSL_HPKE_KEM_derivekey_init(kem,NULL,NULL);
    OSSL_HPKE_KEM_derivekey(kem,&privevp,&pubevp,NULL,0);

    publen = EVP_PKEY_get1_encoded_public_key(pubevp, &pub);
    if (pub == NULL || publen == 0) {
        printf("Error extracting public key - exiting\n");
        exit(0);
    }
    neod_pbuf("pub",pub,publen);
    /*
     * Initial values
     */
#define INFO (char*) "The Info"
    memset(info,MEMCHAR,infolen);
    infolen=strlen(INFO); memcpy(info,INFO,strlen(INFO)); neod_pbuf("info",info,infolen);

#define AAD (char*) "aad aad aad lots and lots of aad"
    memset(aad,MEMCHAR,aadlen);
    aadlen=strlen(AAD); memcpy(aad,AAD,strlen(AAD)); neod_pbuf("aad",aad,aadlen);

#define MESSAGE (char*)"we need another trip to the bottle bank"
    memset(clear,MEMCHAR,clearlen);
    clearlen=strlen(MESSAGE); memcpy(clear,MESSAGE,strlen(MESSAGE)); neod_pbuf("clear",clear,clearlen);
    memset(cipher,MEMCHAR,cipherlen);

    /*
     * Call NSS encrypt
     */
    rv=nss_enc(
        pskid, psklen, psk,
        publen, pub,
        0, NULL,
        clearlen, clear,
        aadlen, aad,
        infolen, info,
        &enclen, enc,
        &cipherlen, cipher
        );
    if (rv!=1) {
        printf("Error Encrypting (%d) - exiting\n",rv);
        exit(rv);
    }
    neod_pbuf("enc",enc,enclen);
    neod_pbuf("ciphertext",cipher,cipherlen);

    /* note that providing "AES_128_GCM" below causes a core dump */
    /* Call HPKE decrypt */
    rv=OSSL_HPKE_recipient_open(kem,
                recclear,&recclearlen,
                enc,enclen,privevp,
                "SHA256","AES-128-GCM",
                info, infolen,
                cipher,cipherlen,
                aad,aadlen,
                NULL, NULL);
    if (rv!=1) {
        printf("Error decrypting (%d)\n",rv);
    } else {
        neod_pbuf("recovered clear",recclear,recclearlen);
    }

    OSSL_HPKE_KEM_free(kem);
    EVP_PKEY_free(privevp);
    EVP_PKEY_free(pubevp);
    OPENSSL_free(pub);

    return 1;
}
