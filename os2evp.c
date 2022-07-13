
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include "hpke.h"

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

int main(int argc, char *argv[])
{
    size_t oslen=0; unsigned char *os = NULL;
    EVP_PKEY *sk = NULL;
    size_t lpublen = 0;
    unsigned char *lpub = NULL;
    unsigned char *nprivbuf; size_t nprivlen=0;
    unsigned char *npubbuf; size_t npublen=0;
    unsigned char *xprivbuf; size_t xprivlen=0;
    unsigned char *xpubbuf; size_t xpublen=0;

    ah_decode(strlen(nprivstr),nprivstr,&nprivlen,&nprivbuf);
    ah_decode(strlen(npubstr),npubstr,&npublen,&npubbuf);
    ah_decode(strlen(xprivstr),xprivstr,&xprivlen,&xprivbuf);
    ah_decode(strlen(xpubstr),xpubstr,&xpublen,&xpubbuf);

    if (argc == 1) { /* any CLA turns this off */
        os=xprivbuf;
        oslen=xprivlen;
        /* non-NIST case - this works */
        OSSL_HPKE_prbuf2evp(NULL,0x20,os,oslen,NULL,0,&sk);
        if (sk == NULL) {
            printf("non-NIST 2evp failed\n");
        } else {
            lpublen = EVP_PKEY_get1_encoded_public_key(sk, &lpub);
            if (lpub == NULL || lpublen == 0) {
                printf("non-NIST gep failed\n");
            } else {
                printf("non-NIST gep worked\n\t");
                for (int i=0;i!=lpublen;i++) {
                    printf("%02x",lpub[i]);
                }
                printf("\nhard coded pub:\n\t%s\n",xpubstr);
            }
        }
        EVP_PKEY_free(sk);
        sk=NULL;
    }

    /* NIST case - used to crash, but ok now */
    os=nprivbuf;
    oslen=nprivlen;
    OSSL_HPKE_prbuf2evp(NULL,0x10,os,oslen,NULL,0,&sk);
    if (sk == NULL) {
        printf("NIST 2evp failed\n");
    } else {
        lpublen = EVP_PKEY_get1_encoded_public_key(sk, &lpub);
        if (lpub == NULL || lpublen == 0) {
            printf("NIST gep failed\n");
        } else {
            printf("NIST gep worked\n\t");
            for (int i=0;i!=lpublen;i++) {
                printf("%02x",lpub[i]);
            }
            printf("\nhard coded pub:\n\t%s\n",npubstr);
        }
    }

}

