#include <stddef.h>
#include <string.h>
#include <openssl/hpke.h>
#include <openssl/evp.h>

/*
 * this is big enough for this example, real code would need different
 * handling
 */
#define LBUFSIZE 48

/* Do a round-trip, generating a key, encrypting and decrypting */
int main(int argc, char **argv)
{
    int ok = 0;
    int hpke_mode = OSSL_HPKE_MODE_BASE;
    OSSL_HPKE_SUITE hpke_suite = OSSL_HPKE_SUITE_DEFAULT;
    OSSL_HPKE_CTX *sctx = NULL, *rctx = NULL;
    EVP_PKEY *priv = NULL;
    unsigned char pub[LBUFSIZE];
    size_t publen = sizeof(pub);
    unsigned char enc[LBUFSIZE];
    size_t enclen = sizeof(enc);
    unsigned char ct[LBUFSIZE];
    size_t ctlen = sizeof(ct);
    unsigned char clear[LBUFSIZE];
    size_t clearlen = sizeof(clear);
    const unsigned char *pt = "a message not in a bottle";
    size_t ptlen = strlen((char *)pt);
    const unsigned char *info = "Some info";
    size_t infolen = strlen((char *)info);
    unsigned char aad[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t aadlen = sizeof(aad);

    /*
     * Generate receiver's key pair.
     * The receiver gives this public key to the sender.
     */
    if (OSSL_HPKE_keygen(hpke_suite, pub, &publen, &priv,
                         NULL, 0, NULL, NULL) != 1)
        goto err;

    /* sender's actions - encrypt data using the receivers public key */
    if ((sctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, NULL, NULL)) == NULL)
        goto err;
    if (OSSL_HPKE_encap(sctx, enc, &enclen, pub, publen, info, infolen) != 1)
        goto err;
    if (OSSL_HPKE_seal(sctx, ct, &ctlen, aad, aadlen, pt, ptlen) != 1)
        goto err;

    /* receiver's actions - decrypt data using the recievers private key */
    if ((rctx = OSSL_HPKE_CTX_new(hpke_mode, hpke_suite, NULL, NULL)) == NULL)
        goto err;
    if (OSSL_HPKE_decap(rctx, enc, enclen, priv, info, infolen) != 1)
        goto err;
    if (OSSL_HPKE_open(rctx, clear, &clearlen, aad, aadlen, ct, ctlen) != 1)
        goto err;
    ok = 1;
err:
    /* clean up */
    printf(ok ? "All Good!\n" : "Error!\n");
    OSSL_HPKE_CTX_free(rctx);
    OSSL_HPKE_CTX_free(sctx);
    EVP_PKEY_free(priv);
    return 0;
}
