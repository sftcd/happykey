/*
 * below are the old enc/dec APIs that now dropped from the
 * OpenSSL PR, but preserved here in case that's useful
 */

/* strings for modes */
# define OSSL_HPKE_MODESTR_BASE       "base"    /* base mode (1) */
# define OSSL_HPKE_MODESTR_PSK        "psk"     /* psk mode (2) */
# define OSSL_HPKE_MODESTR_AUTH       "auth"    /* sender-key pair auth (3) */
# define OSSL_HPKE_MODESTR_PSKAUTH    "pskauth" /* psk+sender-key pair (4) */

/*
 * new values for include/openssl/proverr.h
 * require doing a ``make update`` in the openssl
 * tree, if that's not done, we'll re-define it
 * locally
 */
#ifndef PROV_R_INVALID_KDF
# define PROV_R_INVALID_KDF 232
#endif
#ifndef PROV_R_INVALID_AEAD
# define PROV_R_INVALID_AEAD 231
#endif

/* an error macro just to make things easier */
#ifndef ERR_raise
# define ERR_raise(__a__, __b__) \
    { \
        if (erv == 1) { erv = 0; } \
    }
#endif
/* a macro used variously */
#ifndef OSSL_NELEM
# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#endif


/*
 * @brief  Map ascii to binary - utility macro used in >1 place
 */
# define HPKE_A2B(_c_) (_c_ >= '0' && _c_ <= '9' ? (_c_ - '0') :\
                        (_c_ >= 'A' && _c_ <= 'F' ? (_c_ - 'A' + 10) :\
                         (_c_ >= 'a' && _c_ <= 'f' ? (_c_ - 'a' + 10) : 0)))

/*
 * @brief for odd/occasional debugging
 * @param fout is a FILE * to use
 * @param msg is prepended to print
 * @param buf is the buffer to print
 * @param blen is the length of the buffer
 * @return 1 for success, 0 otherwise
 */
int hpke_pbuf(FILE *fout, const char *msg,
                     const unsigned char *buf, size_t blen);


/*
 * @brief run the KEM with two keys as required
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param encrypting is 1 if we're encrypting, 0 for decrypting
 * @param suite is the ciphersuite
 * @param key1 is the first key, for which we have the private value
 * @param key1enclen is the length of the encoded form of key1
 * @param key1en is the encoded form of key1
 * @param key2 is the peer's key
 * @param key2enclen is the length of the encoded form of key1
 * @param key2en is the encoded form of key1
 * @param akey is the authentication private key
 * @param apublen is the length of the encoded the authentication public key
 * @param apub is the encoded form of the authentication public key
 * @param ss is (a pointer to) the buffer for the shared secret result
 * @param sslen is the size of the buffer (octets-used on exit)
 * @return 1 for success, 0 otherwise
 */
int hpke_do_kem(OSSL_LIB_CTX *libctx, const char *propq,
                int encrypting, OSSL_HPKE_SUITE suite,
                EVP_PKEY *key1,
                size_t key1enclen, const unsigned char *key1enc,
                EVP_PKEY *key2,
                size_t key2enclen, const unsigned char *key2enc,
                EVP_PKEY *akey,
                size_t apublen, const unsigned char *apub,
                unsigned char **ss, size_t *sslen);

/**
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output that can be sent to
 * the relevant private key holder along with the ciphertext.
 *
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
 * @param psk is the psk
 * @param psklen is the psk length
 * @param pub is the encoded public key
 * @param publen is the length of the public key
 * @param authpriv is the encoded private (authentication) key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clear is the encoded cleartext
 * @param clearlen is the length of the cleartext
 * @param aad is the encoded additional data
 * @param aadlen is the length of the additional data
 * @param info is the encoded info data (can be NULL)
 * @param infolen is the length of the info data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param senderpub is the input buffer for sender public key
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpriv is the sender's private key (if being re-used)
 * @param cipher is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_enc(OSSL_LIB_CTX *libctx, const char *propq,
                  unsigned int mode, OSSL_HPKE_SUITE suite,
                  const char *pskid,
                  const unsigned char *psk, size_t psklen,
                  const unsigned char *pub, size_t publen,
                  const unsigned char *authpriv, size_t authprivlen,
                  EVP_PKEY *authpriv_evp,
                  const unsigned char *clear, size_t clearlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *info, size_t infolen,
                  const unsigned char *seq, size_t seqlen,
                  unsigned char *senderpub, size_t *senderpublen,
                  EVP_PKEY *senderpriv,
                  unsigned char *cipher, size_t *cipherlen);

/**
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param propq is a properties string
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string for a PSK mode (can be NULL)
 * @param psk is the psk
 * @param psklen is the psk length
 * @param pub is the encoded public (authentication) key
 * @param publen is the length of the public (authentication) key
 * @param priv is the encoded private key
 * @param privlen is the length of the private key
 * @param evppriv is a pointer to an internal form of private key
 * @param enc is the peer's public value
 * @param enclen is the length of the peer's public value
 * @param cipher is the ciphertext
 * @param cipherlen is the length of the ciphertext
 * @param aad is the encoded additional data
 * @param aadlen is the length of the additional data
 * @param info is the encoded info data (can be NULL)
 * @param infolen is the length of the info data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param clear is the encoded cleartext
 * @param clearlen length of the input buffer for cleartext
 * @return 1 for success, other for error (error returns can be non-zero)
 */
int OSSL_HPKE_dec(OSSL_LIB_CTX *libctx, const char *propq,
                  unsigned int mode, OSSL_HPKE_SUITE suite,
                  const char *pskid, const unsigned char *psk, size_t psklen,
                  const unsigned char *pub, size_t publen,
                  const unsigned char *priv, size_t privlen, EVP_PKEY *evppriv,
                  const unsigned char *enc, size_t enclen,
                  const unsigned char *cipher, size_t cipherlen,
                  const unsigned char *aad, size_t aadlen,
                  const unsigned char *info, size_t infolen,
                  const unsigned char *seq, size_t seqlen,
                  unsigned char *clear, size_t *clearlen);

/**
 * @brief set a sender KEM private key for HPKE
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 *
 * If no key is set via this API an ephemeral one will be
 * generated in the first seal operation and used until the
 * context is free'd. (Or until a subsequent call to this
 * API replaces the key.) This suits senders who are typically
 * clients.
 */
int OSSL_HPKE_CTX_set1_senderpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *privp);

const char *kem_info_str(const OSSL_HPKE_KEM_INFO *kem_info);
const char *kdf_info_str(const OSSL_HPKE_KDF_INFO *kdf_info);
const char *aead_info_str(const OSSL_HPKE_AEAD_INFO *aead_info);
extern const char *hpke_mode_strtab[4];
