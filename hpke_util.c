/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#ifdef HAPPYKEY
#include "hpke_util.h"
#include "packet.h"
#else
#include "internal/hpke_util.h"
#include "internal/packet.h"
#endif

/* ASCII: "HPKE-v1", in hex for EBCDIC compatibility */
static const char LABEL_HPKEV1[] = "\x48\x50\x4B\x45\x2D\x76\x31";

static int kdf_derive(EVP_KDF_CTX *kctx,
                      unsigned char *out, size_t outlen, int mode,
                      const unsigned char *salt, size_t saltlen,
                      const unsigned char *ikm, size_t ikmlen,
                      const unsigned char *info, size_t infolen)
{
    int ret;
    OSSL_PARAM params[5], *p = params;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    if (salt != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                 (char *)salt, saltlen);
    if (ikm != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 (char *)ikm, ikmlen);
    if (info != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                 (char *)info, infolen);
    *p = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(kctx, out, outlen, params) > 0;
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
    return ret;
}

int ossl_hpke_kdf_extract(EVP_KDF_CTX *kctx,
                          unsigned char *prk, size_t prklen,
                          const unsigned char *salt, size_t saltlen,
                          const unsigned char *ikm, size_t ikmlen)
{
    return kdf_derive(kctx, prk, prklen, EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
                      salt, saltlen, ikm, ikmlen, NULL, 0);
}

/* Common code to perform a HKDF expand */
int ossl_hpke_kdf_expand(EVP_KDF_CTX *kctx,
                         unsigned char *okm, size_t okmlen,
                         const unsigned char *prk, size_t prklen,
                         const unsigned char *info, size_t infolen)
{
    return kdf_derive(kctx, okm, okmlen, EVP_KDF_HKDF_MODE_EXPAND_ONLY,
                      NULL, 0, prk, prklen, info, infolen);
}

/*
 * See RFC 9180 Section 4 LabelExtract()
 */
int ossl_hpke_labeled_extract(EVP_KDF_CTX *kctx,
                              unsigned char *prk, size_t prklen,
                              const unsigned char *salt, size_t saltlen,
                              const char *protocol_label,
                              const unsigned char *suiteid, size_t suiteidlen,
                              const char *label,
                              const unsigned char *ikm, size_t ikmlen)
{
    int ret = 0;
    size_t labeled_ikmlen = 0;
    unsigned char *labeled_ikm = NULL;
    WPACKET pkt;

    labeled_ikmlen = strlen(LABEL_HPKEV1) + strlen(protocol_label)
        + suiteidlen + strlen(label) + ikmlen;
    labeled_ikm = OPENSSL_malloc(labeled_ikmlen);
    if (labeled_ikm == NULL)
        return 0;

    /* labeled_ikm = concat("HPKE-v1", suiteid, label, ikm) */
    if (!WPACKET_init_static_len(&pkt, labeled_ikm, labeled_ikmlen, 0)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, protocol_label, strlen(protocol_label))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, ikm, ikmlen)
            || !WPACKET_get_total_written(&pkt, &labeled_ikmlen)
            || !WPACKET_finish(&pkt)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }

    ret = ossl_hpke_kdf_extract(kctx, prk, prklen, salt, saltlen,
                                labeled_ikm, labeled_ikmlen);
end:
    WPACKET_cleanup(&pkt);
    OPENSSL_cleanse(labeled_ikm, labeled_ikmlen);
    OPENSSL_free(labeled_ikm);
    return ret;
}

/*
 * See RFC 9180 Section 4 LabelExpand()
 */
int ossl_hpke_labeled_expand(EVP_KDF_CTX *kctx,
                             unsigned char *okm, size_t okmlen,
                             const unsigned char *prk, size_t prklen,
                             const char *protocol_label,
                             const unsigned char *suiteid, size_t suiteidlen,
                             const char *label,
                             const unsigned char *info, size_t infolen)
{
    int ret = 0;
    size_t labeled_infolen = 0;
    unsigned char *labeled_info = NULL;
    WPACKET pkt;

    labeled_infolen = 2 + okmlen + prklen + strlen(LABEL_HPKEV1)
        + strlen(protocol_label) + suiteidlen + strlen(label) + infolen;
    labeled_info = OPENSSL_malloc(labeled_infolen);
    if (labeled_info == NULL)
        return 0;

    /* labeled_info = concat(okmlen, "HPKE-v1", suiteid, label, info) */
    if (!WPACKET_init_static_len(&pkt, labeled_info, labeled_infolen, 0)
            || !WPACKET_put_bytes_u16(&pkt, okmlen)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, protocol_label, strlen(protocol_label))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, info, infolen)
            || !WPACKET_get_total_written(&pkt, &labeled_infolen)
            || !WPACKET_finish(&pkt)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }

    ret = ossl_hpke_kdf_expand(kctx, okm, okmlen,
                               prk, prklen, labeled_info, labeled_infolen);
end:
    WPACKET_cleanup(&pkt);
    OPENSSL_free(labeled_info);
    return ret;
}

/* Common code to create a HKDF ctx */
EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(libctx, kdfname, propq);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx != NULL && mdname != NULL) {
        OSSL_PARAM params[3], *p = params;

        if (mdname != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                    (char *)mdname, 0);
        if (propq != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES,
                                                    (char *)propq, 0);
        *p = OSSL_PARAM_construct_end();
        if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
            EVP_KDF_CTX_free(kctx);
            return NULL;
        }
    }
    return kctx;
}
