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
 * An OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
 *
 * I plan to use this for my ESNI-enabled OpenSSL build (https://github.com/sftcd/openssl)
 * when the time is right.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "hpke.h"

#ifdef TESTVECTORS
#include "hpketv.h"
#endif

/* Map ascii to binary */
#define HPKE_A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
                        (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))

/**
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ahstr is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return zero for error, 1 for success 
 */
int hpke_ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf)
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

#ifdef TESTVECTORS
/**
 * @brief stdout version of esni_pbuf - just for odd/occasional debugging
 */
static void hpke_pbuf(char *msg,unsigned char *buf,size_t blen) 
{
    if (buf==NULL) {
        printf("%s is NULL\n",msg);
        return;
    }
    printf("%s: ",msg);
    int i;
    for (i=0;i!=blen;i++) {
        printf("%02x",buf[i]);
    }
    printf("\n");
    return;
}
#endif

/*
 * @brief encode binary to ascii hex
 *
 * @param blen is the input buffer length
 * @param buf is the input buffer
 * @para

/*
 * @brief Check if ciphersuite is ok/known to us
 * @param suite is the externally supplied cipheruite
 * @return 1 for good, not-1 for error
 *
 * For now, we only recognise HPKE_SUITE_DEFAULT
 */
static int hpke_suite_check(hpke_suite_t suite)
{
    hpke_suite_t comp=HPKE_SUITE_DEFAULT;
    if (CRYPTO_memcmp(&suite,&comp,sizeof(hpke_suite_t))) return(0);
    return(1);
}

/*
 * @brief return the length of the context for this suite
 * @param suite is the externally supplied cipheruite
 * @return the length (in octets) of the context 
 *
 * For now, we only recognise HPKE_SUITE_DEFAULT
 */
static int figure_context_len(hpke_suite_t suite)
{
    /* for now, I'm using the test vector, we'll see how that goes */
    //return strlen("00000200010001ef0bf7ee58713568663204cf720cff64a852c77ace25f478cfe7dc0721508e03186c394e175b7b161760b1bd5b822a0804bd066b170c695c0df123176fa7df6f0000000000000000000000000000000000000000000000000000000000000000e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85555c4040629c64c5efec2f7230407d612d16289d7c5d7afcf9340280abd2de1ab")/2;
    return(167);
}

/**
 * @brief do the AEAD encryption as per the I-D
 *
 * Note: The tag output isn't really needed but was useful when I got
 * the aad wrong at one stage to keep it for now.
 * Most parameters obvious but...
 *
 * @param cipher_len is an input/output, better be big enough on input, exact on output
 * @param cipher is an output
 * @return 1 for good otherwise bad
 * @returns NULL (on error) or pointer to alloced buffer for ciphertext
 */
static int aead_enc(
            unsigned char *key, size_t key_len,
            unsigned char *iv, size_t iv_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *plain, size_t plain_len,
            unsigned char *cipher, size_t *cipher_len)
{
    /*
     * From https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
     */
    int erv=1;
    EVP_CIPHER_CTX *ctx=NULL;
    int len;
    size_t ciphertext_len;
    unsigned char *ciphertext=NULL;
    size_t tag_len=EVP_GCM_TLS_TAG_LEN;
    unsigned char tag[EVP_GCM_TLS_TAG_LEN]; 

    if (tag_len+plain_len>*cipher_len) {
        erv=__LINE__; goto err;
    }
    /*
     * We'll allocate this much extra for ciphertext and check the AEAD doesn't require more
     * If it does, we'll fail.
     */
    ciphertext=OPENSSL_malloc(plain_len+tag_len);
    if (ciphertext==NULL) {
        erv=__LINE__; goto err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        erv=__LINE__; goto err;
    }
    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc = EVP_aes_128_gcm();
    if (enc == NULL) {
        erv=__LINE__; goto err;
    }
    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        erv=__LINE__; goto err;
    }
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        erv=__LINE__; goto err;
    }
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        erv=__LINE__; goto err;
    }
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aad_len!=0 && aad!=NULL) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            erv=__LINE__; goto err;
        }
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plain_len)) {
        erv=__LINE__; goto err;
    }
    ciphertext_len = len;
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        erv=__LINE__; goto err;
    }
    ciphertext_len += len;
    /*
     * Get the tag
     * This isn't a duplicate so needs to be added to the ciphertext
     *
     * So I had a problem with this code when built with optimisation
     * turned on ("-O3" or even "-g -O1" when I manually edited the
     * Makefile). Valgrind reports use of uninitialised memory
     * related to the tag (when it was later printed in SSL_ESNI_print).
     * When I was just passing in the tag directly, I got a couple
     * of valgrind errors from within SSL_ESNI_print and then loads
     * (>1000) other uninitialised memory errors later on from all
     * sorts of places in code I've not touched for ESNI.
     * For now, building with "no-asm" is a workaround that works
     * around:-)
     * I mailed the openssl-users list:
     * https://mta.openssl.org/pipermail/openssl-users/2019-November/011503.html
     * TODO(ESNI): follow up on this
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) {
        erv=__LINE__; goto err;
    }
    memcpy(ciphertext+ciphertext_len,tag,tag_len);
    ciphertext_len += tag_len;
    /* Clean up */
    if (ciphertext_len>*cipher_len) {
        erv=__LINE__; goto err;
    }
    *cipher_len=ciphertext_len;
    memcpy(cipher,ciphertext,ciphertext_len);
err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ciphertext!=NULL) OPENSSL_free(ciphertext);
    return erv;
}

/*
 * @brief HPKE single-shot encryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param recippublen is the length of the recipient public key
 * @param recippub is the encoded recipient public key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the lenght of the additional data (can be zero)
 * @param aad is the encoded additional data (can be NULL)
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param senderpublen is the length of the input buffer for the sender's public key (length used on output)
 * @param senderpub is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_enc(
        unsigned int mode,
        hpke_suite_t suite,
        size_t recippublen, 
        unsigned char *recippub,
        size_t clearlen,
        unsigned char *clear,
        size_t aadlen,
        unsigned char *aad,
        size_t infolen,
        unsigned char *info,
        size_t *senderpublen,
        unsigned char *senderpub,
        size_t *cipherlen,
        unsigned char *cipher
#ifdef TESTVECTORS
        , hpke_tv_t *tv
#endif
        )
{
    if (mode!=HPKE_MODE_BASE) return(__LINE__);
    if (!hpke_suite_check(suite)) return(__LINE__);
    if (!recippub || !clear || !senderpublen || !senderpub || !cipherlen  || !cipher) return(__LINE__);
    int erv=1; ///< Our error return value - 1 is success

    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. generate sender's key pair
     * 2. run DH KEM to get zz
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD 
     *
     * We'll follow the names used in the test vectors from the draft.
     * For now, we're replicating the setup from Appendix A.2
     * TODO: 1) generalise and 2) refactor to reduce LOC
     */

    /* declare vars - done early so goto err works ok */
    EVP_PKEY_CTX *pctx=NULL;
    EVP_PKEY *pkR=NULL;
    EVP_PKEY *pkE=NULL;
    size_t  zz_len=0;
    unsigned char *zz=NULL;
    size_t  enc_len=0;
    unsigned char *enc=NULL;
    size_t  context_len=0;
    unsigned char *context=NULL;
    size_t  secret_len=0;
    unsigned char *secret=NULL;
    size_t  key_len=0;
    unsigned char *key=NULL;
    size_t  nonce_len=0;
    unsigned char *nonce=NULL;
    size_t clbuf_len=0;
    unsigned char *clbuf=NULL;

    /* step 0 */
    pkR = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,recippub,recippublen);
    if (pkR == NULL) {
        erv=__LINE__; goto err;
    }

    /* step 1 */
    pctx = EVP_PKEY_CTX_new(pkR, NULL);
    if (pctx == NULL) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        erv=__LINE__; goto err;
    }
#ifdef TESTVECTORS
    /*
     * Read secret from tv, then use that instead of 
     * newly generated key pair
     */
    unsigned char *bin_skE=NULL;
    size_t bin_skE_len=0;
    hpke_ah_decode(strlen(tv->skE),tv->skE,&bin_skE_len,&bin_skE);
    pkE = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,NULL,bin_skE,bin_skE_len);
    OPENSSL_free(bin_skE);
    if (!pkE) {
        erv=__LINE__; goto err;
    }
#else
    if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
        erv=__LINE__; goto err;
    }
#endif
    EVP_PKEY_CTX_free(pctx); pctx=NULL;

    enc_len = EVP_PKEY_get1_tls_encodedpoint(pkE,&enc);
    if (enc==NULL || enc_len == 0) {
        erv=__LINE__; goto err;
    }


    /* step 2 */
    pctx = EVP_PKEY_CTX_new(pkE,NULL);
    if (pctx == NULL) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, pkR) <= 0 ) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &zz_len) <= 0) {
        erv=__LINE__; goto err;
    }
    zz=OPENSSL_malloc(zz_len);
    if (zz == NULL) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive(pctx, zz, &zz_len) <= 0) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;

    /* step 3 */
    context_len=figure_context_len(suite);
    /* allocate space incl. some o/h just in case */
    context=OPENSSL_malloc(context_len+1024);
    if (context==NULL) {
        erv=__LINE__; goto err;
    }

#define CHECK_HPKE_CTX if ((cp-context)>context_len) { erv=__LINE__; goto err; }

    /* step 3 */
    unsigned char *cp=context;
    *cp++=mode; CHECK_HPKE_CTX
    memcpy(cp,&suite,sizeof(suite)); cp+=sizeof(suite); CHECK_HPKE_CTX
    memcpy(cp,enc,enc_len); cp+=enc_len; CHECK_HPKE_CTX
    memcpy(cp,recippub,recippublen); cp+=recippublen; CHECK_HPKE_CTX;
    const unsigned char zero_buf[SHA256_DIGEST_LENGTH] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(cp,zero_buf,SHA256_DIGEST_LENGTH); cp+=SHA256_DIGEST_LENGTH; CHECK_HPKE_CTX;
    /* 
     * if you'd like to re-caclulate the sha256 of nothing...
     *  SHA256_CTX sha256;
     *  SHA256_Init(&sha256);
     *  char* buffer = NULL;
     *  int bytesRead = 0;
     *  SHA256_Update(&sha256, buffer, bytesRead);
     *  SHA256_Final(zero_sha256, &sha256);
     * ...but I've done it for you, so no need:-)
     */
    const unsigned char zero_sha256[SHA256_DIGEST_LENGTH] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    memcpy(cp,zero_sha256,SHA256_DIGEST_LENGTH); cp+=SHA256_DIGEST_LENGTH; CHECK_HPKE_CTX;

    /*
     * Bash command line hashing starting from ascii hex example:
     *
     *    $ echo -e "4f6465206f6e2061204772656369616e2055726e" | xxd -r -p | openssl sha256
     *    (stdin)= 55c4040629c64c5efec2f7230407d612d16289d7c5d7afcf9340280abd2de1ab
     *
     * The above generates the Hash(info) used in Appendix A.2
     *
     * If you'd like to regenerate the zero_sha256 value above, feel free
     *    $ echo -n "" | openssl sha256 
     *    echo -n "" | openssl sha256
     *    (stadin)= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     *
     */
    if (info==NULL) {
        memcpy(cp,zero_sha256,SHA256_DIGEST_LENGTH); cp+=SHA256_DIGEST_LENGTH; CHECK_HPKE_CTX;
    } else {
        unsigned char infohash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, info, infolen);
        SHA256_Final(infohash, &sha256);
        memcpy(cp,infohash,SHA256_DIGEST_LENGTH); cp+=SHA256_DIGEST_LENGTH; CHECK_HPKE_CTX;
    }

    /* step 4 */

    /*
     * secret = Extract(psk, zz)
     * in my case psk is 32 octets of zero
     */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_init(pctx)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, zz, zz_len)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, zero_buf, SHA256_DIGEST_LENGTH)!=1) {
        erv=__LINE__; goto err;
    }
    secret_len=SHA256_DIGEST_LENGTH;
    secret=OPENSSL_malloc(secret_len);
    if (!secret) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive(pctx, secret, &secret_len)!=1) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;

    /*
    key = Expand(secret, concat("hpke key", context), Nk)
    */
    clbuf_len=context_len+100;
    clbuf=OPENSSL_malloc(clbuf_len);
    if (!clbuf) {
        erv=__LINE__; goto err;
    }
#define HPKE_KEY_LABEL "hpke key"
    memcpy(clbuf,HPKE_KEY_LABEL,strlen(HPKE_KEY_LABEL));
    memcpy(clbuf+strlen(HPKE_KEY_LABEL),context,context_len);
    clbuf_len=strlen(HPKE_KEY_LABEL)+context_len;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_init(pctx)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, clbuf, clbuf_len)!=1) {
        erv=__LINE__; goto err;
    }
    key_len=16;
    key=OPENSSL_malloc(key_len);
    if (!key) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive(pctx, key, &key_len)!=1) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;

    /*
    nonce = Expand(secret, concat("hpke nonce", context), Nn)
    */
#define HPKE_NONCE_LABEL "hpke nonce"
    memcpy(clbuf,HPKE_NONCE_LABEL,strlen(HPKE_NONCE_LABEL));
    memcpy(clbuf+strlen(HPKE_NONCE_LABEL),context,context_len);
    clbuf_len=strlen(HPKE_NONCE_LABEL)+context_len;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_init(pctx)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, clbuf, clbuf_len)!=1) {
        erv=__LINE__; goto err;
    }
    nonce_len=12;
    nonce=OPENSSL_malloc(nonce_len);
    if (!nonce) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive(pctx, nonce, &nonce_len)!=1) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;

    /* step 5 */
    size_t lcipherlen=HPKE_MAXSIZE;
    unsigned char lcipher[HPKE_MAXSIZE];
    int arv=aead_enc(
                key,key_len,
                nonce,nonce_len,
                aad,aadlen,
                clear,clearlen,
                lcipher,&lcipherlen);
    if (arv!=1) {
        erv=arv; goto err;
    }
    if (lcipherlen > *cipherlen) {
        erv=__LINE__; goto err;
    }
    memcpy(cipher,lcipher,lcipherlen);
    *cipherlen=lcipherlen;

#ifdef TESTVECTORS
    /*
     * print stuff
     */
    unsigned char *pbuf;
    size_t pblen=1024;
    printf("Runtime:\n");
    printf("\tmode: %d, suite; %d,%d,%d\n",mode,suite.kdf_id,suite.kem_id,suite.aead_id);
    pblen = EVP_PKEY_get1_tls_encodedpoint(pkR,&pbuf); hpke_pbuf("\tpkR",pbuf,pblen); OPENSSL_free(pbuf);
    hpke_pbuf("\tcontext",context,context_len);
    hpke_pbuf("\tzz",zz,zz_len);
    hpke_pbuf("\tsecret",secret,secret_len);
    hpke_pbuf("\tenc",enc,enc_len);
    hpke_pbuf("\tinfo",info,infolen);
    hpke_pbuf("\taad",aad,aadlen);
    hpke_pbuf("\tnonce",nonce,nonce_len);
    hpke_pbuf("\tkey",key,key_len);
    pblen = EVP_PKEY_get1_tls_encodedpoint(pkE,&pbuf); hpke_pbuf("\tpkE",pbuf,pblen); OPENSSL_free(pbuf);
    hpke_pbuf("\tplaintext",clear,clearlen);
    hpke_pbuf("\tciphertext",cipher,*cipherlen);
    //pblen = EVP_PKEY_get1_tls_encodedpoint(skE,&pbuf); hpke_pbuf("\tskE",pbuf,pblen); OPENSSL_free(pbuf);
#endif
    /* 
     * finish up
     */
err:
    /*
     * Free things up
     */
    if (pkR!=NULL) EVP_PKEY_free(pkR);
    if (pkE!=NULL) EVP_PKEY_free(pkE);
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    if (zz!=NULL) OPENSSL_free(zz);
    if (enc!=NULL) OPENSSL_free(enc);
    if (context!=NULL) OPENSSL_free(context);
    if (secret!=NULL) OPENSSL_free(secret);
    if (key!=NULL) OPENSSL_free(key);
    if (nonce!=NULL) OPENSSL_free(nonce);
    if (clbuf!=NULL) OPENSSL_free(clbuf);
    return erv;
}

/*
 * @brief HPKE single-shot decryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param privlen is the length of the private key
 * @param priv is the encoded private key
 * @param cipherlen is the length of the ciphertext 
 * @param cipher is the ciphertext
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param clearlen is the length of the input buffer for cleartext (octets used on output)
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_dec(
        unsigned int mode,
        hpke_suite_t suite,
        size_t privlen, 
        unsigned char *priv,
        size_t cipherlen,
        unsigned char *cipher,
        size_t aadlen,
        unsigned char *aad,
        size_t *clearlen,
        unsigned char *clear)
{
    if (mode!=HPKE_MODE_BASE) return(__LINE__);
    int internal_suite=hpke_suite_check(suite); 
    if (!internal_suite) return(__LINE__);
    if (!priv || !clearlen || !clear || !cipher) return(__LINE__);
    return 0;
}
