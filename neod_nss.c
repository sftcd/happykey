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
 * A round-trip test using NSS to encrypt and my code to decrypt.
 * (Because that doesn't work in my ECH code currently;-)
 *
 * This one has the NSS code, to avoid header file conflicts
 *
 */

/*
 * NSS inlcudes
 */
//#include "blapi.h"
#include "nspr.h"
#include "nss.h"
//#include "nss_scoped_ptrs.h"
#include "keythi.h"
#include "secoid.h"
#include "pkcs11t.h"
#include "pk11hpke.h"
#include "pk11pub.h"
//#include "secerr.h"
//#include "sechash.h"
//#include "testvectors/hpke-vectors.h"
//#include "util.h"


int my_nss_init(void)
{
    int rv=1;

    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    // was PK11_SetPasswordFunc(SECU_GetModulePassword); in tstclnt.c, might need that later
    PK11_SetPasswordFunc(NULL);

    NSS_NoDB_Init(NULL);

    return rv;
}


int nss_enc(
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t *senderpublen, unsigned char *senderpub,
        size_t *cipherlen, unsigned char *cipher
        )
{
    HpkeContext *cx = NULL;
    SECItem aad_item = {siBuffer, aad, aadlen};
    SECKEYPublicKey *pkR = NULL;
    SECItem hpkeInfo = { siBuffer, info, infolen };
    SECStatus rv;
    SECItem chPt = { siBuffer, clear, clearlen};
    SECItem *chCt = NULL;
    const SECItem *hpkeEnc = NULL;

    rv=my_nss_init();
    if (rv != 1) {
        return __LINE__;
    }

    cx = PK11_HPKE_NewContext(0x20,0x01,0x01,NULL,NULL);
    if (cx==NULL) {
        return __LINE__;
    }
    rv = PK11_HPKE_Deserialize(cx, pub, publen, &pkR); 
    if (rv != SECSuccess) {
        return __LINE__;
    }
    rv = PK11_HPKE_SetupS(cx, NULL, NULL, pkR, &hpkeInfo);
    if (rv != SECSuccess) {
        return __LINE__;
    }

    hpkeEnc = PK11_HPKE_GetEncapPubKey(cx);
    if (!hpkeEnc) {
        return __LINE__;
    }
    if (hpkeEnc->len>*senderpublen) {
        return __LINE__;
    }
    *senderpublen=hpkeEnc->len;
    memcpy(senderpub,hpkeEnc->data,*senderpublen);

    rv = PK11_HPKE_Seal(cx, &aad_item, &chPt, &chCt);
    if (rv != SECSuccess) {
        return __LINE__;
    }
    if (chCt->len>*cipherlen) {
        return __LINE__;
    }
    *cipherlen=chCt->len;
    memcpy(cipher,chCt->data,*cipherlen);

    return 1;
}
