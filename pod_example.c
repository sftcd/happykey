#include <stddef.h>
#include <string.h>
#include <openssl/hpke.h>
#include <openssl/evp.h>

/* this is sample code for inclusio in OSSL_HPKE_CTX_new.pod */

/* 
 * this is big enough for this example, real code would need different 
 * handling
 */
#define LBUFSIZE 48

/* we'll do a round-trip, generating a key, encrypting and decrypting */
int main(int argc, char **argv)
{
    int hpke_mode=OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *ctx = NULL, *rctx = NULL;
    size_t publen=LBUFSIZE; unsigned char pub[LBUFSIZE];
    EVP_PKEY *priv = NULL;
    size_t enclen=LBUFSIZE; unsigned char enc[LBUFSIZE];
    size_t ctlen=LBUFSIZE; unsigned char ct[LBUFSIZE];
    size_t ptlen=LBUFSIZE; unsigned char pt[LBUFSIZE];
    size_t clearlen=LBUFSIZE; unsigned char clear[LBUFSIZE];
    size_t aadlen=LBUFSIZE; unsigned char aad[LBUFSIZE];
    size_t infolen=LBUFSIZE; unsigned char info[LBUFSIZE];

    memset(pt,0,LBUFSIZE);
    memset(aad,0,LBUFSIZE);
    memset(info,0,LBUFSIZE);
    strcpy((char*)pt,"a message not in a bottle");
    ptlen=strlen((char*)pt);

    /* generate receiver's key pair */
    if (OSSL_HPKE_keygen(NULL, NULL, hpke_suite, NULL, 0,
                         pub, &publen, &priv) != 1)
        goto err;

    /* sender's actions */
    if ((ctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, NULL, NULL)) == NULL)
        goto err;
    if (OSSL_HPKE_encap(ctx, enc, &enclen, pub, publen, info, infolen) != 1)
        goto err;
    if (OSSL_HPKE_seal(ctx, ct, &ctlen, aad, aadlen, pt, ptlen) != 1)
        goto err;

    /* receiver's actions */
    if ((rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, NULL, NULL)) == NULL)
        goto err;
    if (OSSL_HPKE_decap(rctx, enc, enclen, priv, info, infolen) != 1) 
        goto err;
    if (OSSL_HPKE_open(rctx, clear, &clearlen, aad, aadlen, ct, ctlen) != 1)
        goto err;
    OSSL_HPKE_CTX_free(rctx);
    OSSL_HPKE_CTX_free(ctx);
    EVP_PKEY_free(priv);
    printf("All good\n");
    return 1;

err:
    /* clean up */
    printf("Error!\n");
    OSSL_HPKE_CTX_free(rctx);
    OSSL_HPKE_CTX_free(ctx);
    EVP_PKEY_free(priv);
    return 0;
}
