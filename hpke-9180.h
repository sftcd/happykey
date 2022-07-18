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

OSSL_HPKE_CTX * OSSL_HPKE_CTX_new(const OSSL_LIB_CTX *libctx, int mode);
int OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx);

/*
 * def DeriveKeyPair(ikm)
 * provide ikm/ikmlen as NULL/0 for random key gen
 * provide either privlen/priv or pkey as non-NULL
 * to get the private value in the desired format
 */
int OSSL_HPKE_DeriveKeyPair(OSSL_HPKE_CTX * ctx,
                            OSSL_HPKE_SUITE suite,
                            const unsigned char *ikm, size_t ikmlen,
                            unsigned char *pub, size_t *publen,
                            unsigned char *priv, size_t *privlen,
                            EVP_PKEY *pkey);

/*
 * Add stuff to context (basically the elipsis from
 * the RFC APIs:-)
 */
int OSSL_HPKE_set1_Info(OSSL_HPKE_CTX *ctx,
                        const unsigned char *info, size_t infolen);
int OSSL_HPKE_set1_PSK(OSSL_HPKE_CTX *ctx,
                       const unsigned char *psk, size_t psklen,
                       const char *psk_id);
/*
 * public values can be 0/NULL
 * private value: same convention as derive
 */
int OSSL_HPKE_set1_AuthKey(OSSL_HPKE_CTX *ctx,
                           const unsigned char *skspub, size_t skspublen,
                           const unsigned char *sks, size_t skslen,
                           const EVP_PKEY *sksp);

/*
 * def SetupBaseS(pkR, info):
 * def SetupPSKS(pkR, info, psk, psk_id):
 * def SetupAuthS(pkR, info, skS):
 * def SetupAuthPSKS(pkR, info, psk, psk_id, skS):
 */
int OSSL_HPKE_SetupS(OSSL_HPKE_CTX *ctx,
                     const unsigned char *pkr, size_t pkrlen);

/*
 * def SetupBaseR(enc, skR, info):
 * def SetupPSKR(enc, skR, info, psk, psk_id):
 * def SetupAuthR(enc, skR, info, pkS):
 * def SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS):
 */
int OSSL_HPKE_SetupR(OSSL_HPKE_CTX *ctx,
                     const unsigned char *skr, size_t skrlen,
                     const EVP_PKEY *skrp);

/*
 * def Seal<MODE>(pkR, info, aad, pt, ...):
 * def ContextS.Seal(aad, pt):
 */
int OSSL_HPKE_Seal(OSSL_HPKE_CTX *ctx,
                   OSSL_HPKE_SUITE suite,
                   const unsigned char *plain, size_t plainlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *seq, size_t seqlen,
                   unsigned char *enc, size_t *enclen,
                   unsigned char *cipher, size_t *cipherlen);

/*
 * def Open<MODE>(enc, skR, info, aad, ct, ...):
 * def ContextR.Open(aad, ct):
 */
int OSSL_HPKE_Open(OSSL_HPKE_CTX *ctx,
                   OSSL_HPKE_SUITE suite,
                   const unsigned char *enc, size_t enclen,
                   const unsigned char *cipher, size_t cipherlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *seq, size_t seqlen,
                   unsigned char *plain, size_t *plainlen);

/* def LabeledExpand(prk, label, info, L): */
int OSSL_HPKE_Expand(OSSL_HPKE_CTX *ctx,
                     const unsigned char *prk, size_t prklen,
                     const char *label, size_t labellen,
                     const unsigned char *info, size_t infolen,
                     uint32_t L,
                     unsigned char *out, size_t *outlen);

/* def LabeledExtract(salt, label, ikm): */
int OSSL_HPKE_Extract(OSSL_HPKE_CTX *ctx,
                      const unsigned char *salt, size_t saltlen,
                      const char *label, size_t labellen,
                      const unsigned char *ikm, size_t ikmlen,
                      unsigned char *secret, size_t *secretlen);

/* def Context.Export(exporter_context, L): */
int OSSL_HPKE_Export(OSSL_HPKE_CTX *ctx,
                     const unsigned char *inp, size_t inp_len,
                     size_t L,
                     unsigned char *exporter, size_t *exporter_len);

/*
 * These remaining APIs belwow can be implemented using the above,
 * so no big need for 'em
 *
 * def ReceiveExport<MODE>(enc, skR, info, exporter_context, L, ...):
 * def SendExport<MODE>(pkR, info, exporter_context, L, ...):
 */
