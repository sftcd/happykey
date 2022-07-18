/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/hpke.h>

/* opaque pointer to HPKE context */
typedef void * OSSL_HPKE_CTX;

int OSSL_HPKE_CTX_new(OSSL_LIB_CTX *libctx, int mode);
int OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);

/* 
 * def DeriveKeyPair(ikm) 
 * provide ikm/ikmlen as NULL/0 for random key gen
 * provide either privlen/priv or pkey as non-NULL
 * to get the private value in the desired format
 */ 
int OSSL_HPKE_DeriverKeyPair(OSSL_HPKE_CTX * ctx,
                             OSSL_HPKE_SUITE suite,
                             size_t ikmlen, unsigned char *ikm,
                             size_t *publen, unsigned char *pub,
                             size_t *privlen, unsigned char *priv,
                             EVP_PKEY *pkey);

/*
 * Add stuff to context (basically the elipsis from
 * the RFC APIs:-)
 */
int OSSL_HPKE_Add_Info(OSSL_HPKE_CTX *ctx,
                       size_t infolen,
                       unsigned char *info);
int OSSL_HPKE_Add_PSK(OSSL_HPKE_CTX *ctx,
                      size_t psklen,
                      unsigned char *psk,
                      char *psk_id);
/*
 * public values can be 0/NULL
 * private value: same convention as derive
 */
int OSSL_HPKE_Add_AuthKey(OSSL_HPKE_CTX *ctx,
                          size_t skspublen, unsigned char *skspub,
                          size_t skslen, unsigned char *sks, EVP_PKEY *sksp);

/*
 * def SetupBaseS(pkR, info):
 * def SetupPSKS(pkR, info, psk, psk_id):
 * def SetupAuthS(pkR, info, skS):
 * def SetupAuthPSKS(pkR, info, psk, psk_id, skS):
 */
int OSSL_HPKE_SetupS(OSSL_HPKE_CTX *ctx, size_t pkrlen, unsigned char *pkr);

/*
 * def SetupBaseR(enc, skR, info):
 * def SetupPSKR(enc, skR, info, psk, psk_id):
 * def SetupAuthR(enc, skR, info, pkS):
 * def SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS):
 */
int OSSL_HPKE_SetupR(OSSL_HPKE_CTX *ctx,
                     size_t enclen, unsigned char *enc,
                     size_t skrlen, unsigned char *skr, EVP_PKEY *skrp);

/*
 * def Seal<MODE>(pkR, info, aad, pt, ...):
 * def ContextS.Seal(aad, pt):
 */
int OSSL_HPKE_Seal(OSSL_HPKE_CTX *ctx,
                   OSSL_HPKE_SUITE suite,
                   size_t plainlen, unsigned char *plain,
                   size_t aadlen, unsigned char *aad,
                   size_t seqlen, unsigned char *seq,
                   size_t *enclen, unsigned char *enc,
                   size_t *cipherlen, unsigned char *cipher);

/*
 * def Open<MODE>(enc, skR, info, aad, ct, ...):
 * def ContextR.Open(aad, ct):
 */
int OSSL_HPKE_Open(OSSL_HPKE_CTX *ctx,
                   OSSL_HPKE_SUITE suite,
                   size_t enclen, unsigned char *enc,
                   size_t cipherlen, unsigned char *cipher,
                   size_t aadlen, unsigned char *aad,
                   size_t seqlen, unsigned char *seq,
                   size_t *plainlen, unsigned char *plain);

/* def LabeledExpand(prk, label, info, L): */
int OSSL_HPKE_expand(OSSL_HPKE_CTX *ctx,
                     const unsigned char *prk, const size_t prklen,
                     const char *label, const size_t labellen,
                     const unsigned char *info, const size_t infolen,
                     const uint32_t L,
                     unsigned char *out, size_t *outlen);

/* def LabeledExtract(salt, label, ikm): */
int OSSL_HPKE_extract(OSSL_HPKE_CTX *ctx,
                      const unsigned char *salt, const size_t saltlen,
                      const char *label, const size_t labellen,
                      const unsigned char *ikm, const size_t ikmlen,
                      unsigned char *secret, size_t *secretlen);

/* def Context.Export(exporter_context, L): */
int OSSL_HPKE_export(OSSL_HPKE_CTX *ctx,
                     unsigned char *inp,
                     size_t inp_len,
                     size_t L,
                     unsigned char *exporter,
                     size_t *exporter_len);

/*
 * These remaining APIs belwow can be implemented using the above,
 * so no big need for 'em
 *
 * def ReceiveExport<MODE>(enc, skR, info, exporter_context, L, ...):
 * def SendExport<MODE>(pkR, info, exporter_context, L, ...):
 */
