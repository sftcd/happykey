#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include "hpke.h"

/*
 * Generate keys using private key only - now integrated into apitest.c so
 * DON'T EDIT THIS EDIT THAT
 */

/*
 * NIST p256 key pair from HPKE-07 test vectors
 */
static unsigned char n256priv[] = {
    0x03, 0xe5, 0x2d, 0x22, 0x61, 0xcb, 0x7a, 0xc9,
    0xd6, 0x98, 0x11, 0xcd, 0xd8, 0x80, 0xee, 0xe6,
    0x27, 0xeb, 0x9c, 0x20, 0x66, 0xd0, 0xc2, 0x4c,
    0xfb, 0x33, 0xde, 0x82, 0xdb, 0xe2, 0x7c, 0xf5
};
static unsigned char n256pub[] = {
    0x04, 0x3d, 0xa1, 0x6e, 0x83, 0x49, 0x4b, 0xb3,
    0xfc, 0x81, 0x37, 0xae, 0x91, 0x71, 0x38, 0xfb,
    0x7d, 0xae, 0xbf, 0x8a, 0xfb, 0xa6, 0xce, 0x73,
    0x25, 0x47, 0x89, 0x08, 0xc6, 0x53, 0x69, 0x0b,
    0xe7, 0x0a, 0x9c, 0x9f, 0x67, 0x61, 0x06, 0xcf,
    0xb8, 0x7a, 0x5c, 0x3e, 0xdd, 0x12, 0x51, 0xc5,
    0xfa, 0xe3, 0x3a, 0x12, 0xaa, 0x2c, 0x5e, 0xb7,
    0x99, 0x14, 0x98, 0xe3, 0x45, 0xaa, 0x76, 0x60,
    0x04
};

/*
 * X25519 key pair from HPKE-07 test vectors
 */
static unsigned char x25519priv[] = {
    0x6c, 0xee, 0x2e, 0x27, 0x55, 0x79, 0x07, 0x08,
    0xa2, 0xa1, 0xbe, 0x22, 0x66, 0x78, 0x83, 0xa5,
    0xe3, 0xf9, 0xec, 0x52, 0x81, 0x04, 0x04, 0xa0,
    0xd8, 0x89, 0xa0, 0xed, 0x3e, 0x28, 0xde, 0x00
};
static unsigned char x25519pub[] = {
    0x95, 0x08, 0x97, 0xe0, 0xd3, 0x7a, 0x8b, 0xdb,
    0x0f, 0x21, 0x53, 0xed, 0xf5, 0xfa, 0x58, 0x0a,
    0x64, 0xb3, 0x99, 0xc3, 0x9f, 0xbb, 0x3d, 0x01,
    0x4f, 0x80, 0x98, 0x33, 0x52, 0xa6, 0x36, 0x17
};

/*
 * @brief test generation of pair based on private key
 * @param kem_id the KEM to use (RFC9180 code point)
 * @priv is the private key buffer
 * @privlen is the length of the private key
 * @pub is the public key buffer
 * @publen is the length of the public key
 * @return 1 for good, 0 otherwise
 *
 * This calls OSSL_HPKE_prbuf2evp without specifying the
 * public key, then extracts the public key using the
 * standard EVP_PKEY_get1_encoded_public_key API and then
 * compares that public value with the already-known public
 * value that was input.
 */
static int test_hpke_one_key_gen_from_priv(uint16_t kem_id,
                                           unsigned char *priv, size_t privlen,
                                           unsigned char *pub, size_t publen)
{
    int res = 1;
    EVP_PKEY *sk = NULL;
    unsigned char *lpub = NULL;
    size_t lpublen = 1024;

    if (OSSL_HPKE_prbuf2evp(NULL, kem_id, priv, privlen, NULL, 0, &sk) != 1) {
        res = 0;
    }
    if (sk == NULL) {
        res = 0;
    }
    if (res == 1) {
        lpublen = EVP_PKEY_get1_encoded_public_key(sk, &lpub);
        if (lpub == NULL || lpublen == 0) {
            res = 0;
        } else {
            if (lpublen != publen || memcmp(lpub, pub, publen)) {
                res = 0;
            }
            OPENSSL_free(lpub);
        }
    }
    EVP_PKEY_free(sk);
    return (res);
}

/*
 * @brief call hpke_test_one_priv_gen for a couple of known test vectors
 * @return 1 for good, 0 otherwise
 */
static int hpke_test_gen_from_priv()
{
    int res = 0;

    /* NIST P-256 case */
    res = test_hpke_one_key_gen_from_priv(0x10,
                                          n256priv, sizeof(n256priv),
                                          n256pub, sizeof(n256pub));
    if (res != 1) { return (res); }

    /* X25519 case */
    res = test_hpke_one_key_gen_from_priv(0x20,
                                          x25519priv, sizeof(x25519priv),
                                          x25519pub, sizeof(x25519pub));
    if (res != 1) { return (res); }

    return (res);
}

int main(int argc, char *argv[])
{
    int res = 0;

    res = hpke_test_gen_from_priv();
    if (res != 1) {
        printf("Failed\n");
    } else {
        printf("Worked ok\n");
    }

    return (res);
}
