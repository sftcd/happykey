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
 * @param cipher_len is an output
 * @returns NULL (on error) or pointer to alloced buffer for ciphertext
 */
static unsigned char *aead_enc(
            unsigned char *key, size_t key_len,
            unsigned char *iv, size_t iv_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *plain, size_t plain_len,
            size_t *cipher_len)
{
    /*
     * From https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
     */
    EVP_CIPHER_CTX *ctx=NULL;
    int len;
    size_t ciphertext_len;
    unsigned char *ciphertext=NULL;
    size_t tag_len=EVP_GCM_TLS_TAG_LEN;
    unsigned char tag[EVP_GCM_TLS_TAG_LEN]; 

    /*
     * We'll allocate this much extra for ciphertext and check the AEAD doesn't require more
     * If it does, we'll fail.
     */
    size_t alloced_oh=264;

    if (tag_len > alloced_oh) {
        goto err;
    }
    ciphertext=OPENSSL_malloc(plain_len+alloced_oh);
    if (ciphertext==NULL) {
        goto err;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        goto err;
    }

    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc = EVP_aes_128_gcm();
    if (enc == NULL) {
        goto err;
    }

    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        goto err;
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        goto err;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        goto err;
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aad_len!=0 && aad!=NULL) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            goto err;
        }
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plain_len)) {
        goto err;
    }

    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        goto err;
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
        goto err;
    }
    memcpy(ciphertext+ciphertext_len,tag,tag_len);
    ciphertext_len += tag_len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    *cipher_len=ciphertext_len;

    return ciphertext;

err:
    EVP_CIPHER_CTX_free(ctx);
    if (ciphertext!=NULL) OPENSSL_free(ciphertext);
    return NULL;
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
        unsigned char *cipher)
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
     * 5. AEAD 
     *
     * We'll follow the names used in the test vectors from the draft.
     * For now, we're replicating the setup from Appendix A.2
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
    if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
        erv=__LINE__; goto err;
    }
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
#define HPKE_NONCE_LABEL "hpke nonce"
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
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, clbuf, clbuf_len)!=1) {
        erv=__LINE__; goto err;
    }
    key_len=SHA256_DIGEST_LENGTH;
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
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, clbuf, clbuf_len)!=1) {
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
    size_t lcipherlen=0;
    unsigned char *lcipher=aead_enc(key,key_len,
                nonce,nonce_len,
                aad,aadlen,
                clear,clearlen,
                &lcipherlen);
    if (lcipher==NULL) {
        erv=__LINE__; goto err;
    }
    if (lcipherlen > *cipherlen) {
        erv=__LINE__; goto err;
    }
    memcpy(cipher,lcipher,lcipherlen);
    *cipherlen=lcipherlen;

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
