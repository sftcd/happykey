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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "hpke.h"

#ifdef TESTVECTORS
#include "hpketv.h"
#endif

/* command line strings for modes */
#define HPKE_MODESTR_BASE "base" ///< base mode, no sender auth
#define HPKE_MODESTR_PSK "psk" ///< psk mode
#define HPKE_MODESTR_AUTH "auth" ///< sender-key pair
#define HPKE_MODESTR_PSKAUTH "pskauth" ///< psk+sender-key pair

static int verbose=0; ///< global var for verbosity

static void usage(char *prog,char *errmsg) 
{
    if (errmsg) fprintf(stderr,"\nError! %s\n\n",errmsg);
    fprintf(stderr,"HPKE (draft-irtf-cfrg-hpke) tester, options are:\n");
    fprintf(stderr,"Key generaion:\n");
    fprintf(stderr,"\tUsage: %s -k -p private [-P public]\n",prog);
    fprintf(stderr,"Encryption:\n");
    fprintf(stderr,"\tUsage: %s -e -P public [-p private] [-a aad] [-I info]\n",prog);
    fprintf(stderr,"\t\t\t[-i input] [-o output]\n");
    fprintf(stderr,"\t\t\t[-m mode] [-s psk] [-n pskid]\n");
    fprintf(stderr,"Decryption:\n");
    fprintf(stderr,"\tUsage: %s -d -p private [-P public] [-a aad] [-I info]\n",prog);
    fprintf(stderr,"\t\t\t[-m mode] [-s psk] [-n pskid]\n");
    fprintf(stderr,"\t\t\t[-m mode] [-s psk] [-n pskid]\n");
#ifdef TESTVECTORS
    fprintf(stderr,"This version is built with TESTVECTORS\n");
    fprintf(stderr,"\tUsage: %s -T tvspec\n",prog);
    fprintf(stderr,"\ttvspec is not yet implemented, 1st picked for now.\n");
#endif
    fprintf(stderr,"Options:\n");
    fprintf(stderr,"\t-a additional authenticated data file name or actual value\n");
    fprintf(stderr,"\t-d decrypt\n");
    fprintf(stderr,"\t-e encrypt\n");
    fprintf(stderr,"\t-h help\n");
    fprintf(stderr,"\t-I additional info to bind to key - file name or actual value\n");
    fprintf(stderr,"\t-i input file name or actual value (stdin if not specified)\n");
    fprintf(stderr,"\t-k generate key pair\n");
    fprintf(stderr,"\t-P public key file name or base64 or ascii-hex encoded value\n");
    fprintf(stderr,"\t-p private key file name or base64 or ascii-hex encoded value\n");
    fprintf(stderr,"\t-m mode (one of: base,psk,pskauth)\n");
    fprintf(stderr,"\t-n PSK id string\n");
    fprintf(stderr,"\t-o output file name (output to stdout if not specified) \n");
    fprintf(stderr,"\t-s psk file name or base64 or ascii-hex encoded value\n");
#ifdef TESTVECTORS
    fprintf(stderr,"\t-T run a testvector for mode/suite, e.g. \"-T <selector>\"\n");
#endif
    fprintf(stderr,"\t-v verbose output\n");
    fprintf(stderr,"\n");
    fprintf(stderr,"Notes:\n");
    fprintf(stderr,"- Sometimes base64 or ascii-hex decoding might work when you\n");
    fprintf(stderr,"  don't want it to (sorry about that;-)\n");
    fprintf(stderr,"- If a PSK mode is used, both pskid \"-n\" and psk \"-s\" MUST\n");
    fprintf(stderr,"   be supplied\n");
    exit(1);
}

/*
 * @brief strip out newlines from input
 *
 * This could be more generic and strip all whitespace
 * but not sure that'd be right. So this'll do for now:-)
 *
 * @param len is the string length on input and output
 * @param buf is the string
 * @return void
 */
static void strip_newlines(size_t *len, unsigned char *buf)
{
    size_t writep=0;
    size_t nlen=*len;
    size_t elen=nlen;
    for (size_t i=0;i!=nlen;i++) {
        if (buf[i]!='\n' && buf[i]!='\r') {
            buf[writep++]=buf[i];
        } else {
            elen--;
        }
    }
    if (writep<*len) buf[writep]='\0';
    *len=elen;
    return;
}

/*
 * @brief map a user-supplied input to a buffer or stream
 *
 * We'll check for a file name, base64 or ascii-hex encoding
 *
 * @param inp is the input ptr
 * @param outlen is an output length of buffer
 * @param outbuf is an output buffer
 * @param strip whether to strip newlines from input 
 * @return 1 for good, not 1 for bad
 */
static int map_input(const char *inp, size_t *outlen, unsigned char **outbuf, int strip)
{
    if (!outlen || !outbuf) return(__LINE__);
    /* on-stack buffer/length to handle various cases */
    size_t toutlen=HPKE_MAXSIZE;
    unsigned char tbuf[HPKE_MAXSIZE];
    memset(tbuf,0,HPKE_MAXSIZE); /* need this so valgrind doesn't complain about b64 strspn below with short values */
    /* asci hex is easy:-) either case allowed*/
    const char *AH_alphabet="0123456789ABCDEFabcdef\n";
    /* and base64 isn't much harder */
    const char *B64_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n";

    /* if no input, try stdin */
    if (!inp) {
        toutlen=fread(tbuf,1,HPKE_MAXSIZE,stdin);
        if (verbose) fprintf(stderr,"got %ld bytes from stdin\n",toutlen);
        if (!feof(stdin)) return(__LINE__);
    } else {
        toutlen=strlen(inp);
        if (toutlen>HPKE_MAXSIZE) return(__LINE__);
        FILE *fp=fopen(inp,"r"); /* check if inp is file name */
        if (fp) {
            /* that worked - so read file up to max into buffer */
            toutlen=fread(tbuf,1,HPKE_MAXSIZE,fp);
            if (verbose) fprintf(stderr,"got %ld bytes from file %s\n",toutlen,inp);
            if (ferror(fp)) { fclose(fp); return(__LINE__); }
            fclose(fp);
        } else {
            if (verbose) fprintf(stderr,"got %ld bytes direct from commandline %s\n",toutlen,inp);
            memcpy(tbuf,inp,toutlen);
        }
    }
    if (toutlen>HPKE_MAXSIZE) return(__LINE__);

    /* ascii-hex or b64 decode as needed */
    /* try from most constrained to least in that order */
    if (strip) {
        if (toutlen<=strspn(tbuf,AH_alphabet)) {
            strip_newlines(&toutlen,tbuf);
            int adr=hpke_ah_decode(toutlen,tbuf,outlen,outbuf);
            if (!adr) return(__LINE__);
            if (adr==1) {
	            if (verbose) fprintf(stderr,"ah_decode worked for %s - going with that\n",tbuf);
	            return(1);
	        }
	    } 
	    if (toutlen<=strspn(tbuf,B64_alphabet)) {
            strip_newlines(&toutlen,tbuf);
	        *outbuf=OPENSSL_malloc(toutlen);
	        if (!*outbuf) return(__LINE__);
	        *outlen=EVP_DecodeBlock(*outbuf, (unsigned char *)tbuf, toutlen);
	        if (*outlen!=-1) {
	            if (verbose) fprintf(stderr,"base64 decode worked for %s - going with the %ld bytes that provided\n",tbuf,*outlen);
	            return(1);
	        } else {
	            /* base64 decode failed so maybe the content was good as-is */
	            OPENSSL_free(*outbuf);
	            *outbuf=NULL;
	        }
        }
        if (verbose) fprintf(stderr,"decodes failed for %s - going with original\n",tbuf);
    } else {
        if (verbose>1) fprintf(stderr,"going with original: %s\n",tbuf);
    } 
    /* fallback to assuming input is good, as-is */
    *outbuf=OPENSSL_malloc(toutlen);
    if (!*outbuf) return(__LINE__);
    memcpy(*outbuf,tbuf,toutlen);
    *outlen=toutlen;
    return(1);
}

/*
 * Our PEM-like labels
 */
#define HPKE_START_SP "-----BEGIN SENDERPUB-----"
#define HPKE_END_SP "-----END SENDERPUB-----"
#define HPKE_START_CP "-----BEGIN CIPHERTEXT-----"
#define HPKE_END_CP "-----END CIPHERTEXT-----"
#define HPKE_START_PUB "-----BEGIN PUBLIC KEY-----"
#define HPKE_END_PUB "-----END PUBLIC KEY-----"
#define HPKE_START_PRIV "-----BEGIN PRIVATE KEY-----"
#define HPKE_END_PRIV "-----END PRIVATE KEY-----"


/*!
 * @brief write key pair to file or files
 * @param publen is the size of the public key buffer 
 * @param pub is the public value
 * @param privlen is the size of the private key buffer 
 * @param priv is the private key
 * @param privfname is the private key file name (or key pair file name)
 * @param pubfname is the public key file name
 * @return 1 for good
 */
static int hpkemain_write_keys(
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        char *privname, char *pubname)
{
    FILE *fp=NULL;
    size_t frv=0;
    if (!privname) {
        return(__LINE__);
    }
    if (pubname) {
        if ((fp=fopen(pubname,"w"))==NULL) {
            return(__LINE__);
        }
        frv=fwrite(pub,1,publen,fp);
        fclose(fp);
        if (frv!=publen) {
            return(__LINE__);
        }
        if ((fp=fopen(privname,"w"))==NULL) {
            return(__LINE__);
        }
        frv=fwrite(priv,1,privlen,fp);
        fclose(fp);
        if (frv!=privlen) {
            return(__LINE__);
        }
    } else  {
        if ((fp=fopen(privname,"w"))==NULL) {
            return(__LINE__);
        }
        frv=fwrite(priv,1,privlen,fp);
        if (frv!=privlen) {
            fclose(fp);
            return(__LINE__);
        }

        char b64pub[HPKE_MAXSIZE];
        size_t b64publen=HPKE_MAXSIZE;
        if (publen>HPKE_MAXSIZE) {
            fprintf(stderr,"Error key too big %ld bytes\n",publen);
            return(__LINE__);
        }
        fprintf(fp,"%s\n",HPKE_START_PUB);
        b64publen=EVP_EncodeBlock(b64pub, pub, publen);
        frv=fwrite(b64pub,1,b64publen,fp);
        fprintf(fp,"\n%s\n",HPKE_END_PUB);
        fclose(fp);
        if (frv!=b64publen) {
            return(__LINE__);
        }
    }
    return(1);
}


 
/*!
 * @brief write sender public and ciphertext to file
 * @param fname is the filename (stdout used if null or "")
 * @param splen sender public length
 * @param sp sender public
 * @param ctlen ciphertext length
 * @param ct ciphertext
 * @return 1 for successs, other otherwise
 */
static int hpkemain_write_ct(const char *fname,
                const size_t  splen, const unsigned char *sp,
                const size_t  ctlen, const unsigned char *ct) 
{
    FILE *fout=NULL;
    if (fname==NULL || fname[0]=='\0') {
        fout=stdout;
    } else {
        fout=fopen(fname,"w");
    }
    if (fout==NULL) {
        fprintf(stderr,"Error opening %s for write\n",fname);
        return(__LINE__);
    }

    char eb[HPKE_MAXSIZE];
    size_t eblen=HPKE_MAXSIZE;
    if (splen>HPKE_MAXSIZE) {
        fprintf(stderr,"Error key too big %ld bytes\n",splen);
        return(__LINE__);
    }
    eblen=EVP_EncodeBlock(eb, sp, splen);
    fprintf(fout,"%s\n",HPKE_START_SP);
    size_t rrv=fwrite(eb,1,eblen,fout);
    if (rrv!=eblen) {
        fprintf(stderr,"Error writing %ld bytes of output to %s (only %ld written)\n",splen,fname,rrv);
        return(__LINE__);
    }
    fprintf(fout,"\n%s\n",HPKE_END_SP);
    fprintf(fout,"%s\n",HPKE_START_CP);
    if (ctlen>HPKE_MAXSIZE) {
        fprintf(stderr,"Error ciphertext too big %ld bytes\n",ctlen);
        return(__LINE__);
    }
    eblen=EVP_EncodeBlock(eb, ct, ctlen);
    rrv=fwrite(eb,1,eblen,fout);
    if (rrv!=eblen) {
        fprintf(stderr,"Error writing %ld bytes of output to %s (only %ld written)\n",ctlen,fname,rrv);
        return(__LINE__);
    }
    fprintf(fout,"\n%s\n",HPKE_END_CP);
    fclose(fout);
    return(1);
}

/*!
 * @brief read sender public and ciphertext to file
 *
 * An example of our home-grown PEM-like format is
 * below:
 *
 * -----BEGIN SENDERPUB-----
 * btLLL0obGXN9AAs395USTenEKx5iAHriosas2+TMm0Y=
 * -----END SENDERPUB-----
 * -----BEGIN CIPHERTEXT-----
 * j+NFQjYKmDEa4IwrsPkhPq7Nr+GjhtbdRMFToG1b0+a0jWyoikOTeXSovDaW0f8Ns
 * uJSJ6BEC7ub9g3UE+oJWeYzzlP6PjI9d52qmDb0gRwjnQ==
 * -----END CIPHERTEXT-----
 *
 * Our decoding rules are:
 * - file size < HPKE_MAXSIZE (640kb)
 * - labels MUST be in that order
 * - we'll chew any whitespace between labels before
 *   attempting base64 decode
 *
 * @param fname is the filename (stdin used if null or "")
 * @param splen sender public buffer size (modified on output)
 * @param sp sender public (allocated by calller)
 * @param ctlen ciphertext buffer size (modified on output)
 * @param ct ciphertext (allocated by caller)
 * @return 1 for successs, other otherwise
 */
static int hpkemain_read_ct(const char *fname,
                size_t  *splen, unsigned char *sp,
                size_t  *ctlen, unsigned char *ct) 
{
    FILE *fin=NULL;
    char fbuf[HPKE_MAXSIZE]; 
    const char *pfname=fname;
    if (!fname || fname[0]=='\0') {
        fin=stdin;
        pfname="STDIN";
    } else {
        fin=fopen(fname,"rb");
        if (!fin) {
            fprintf(stderr,"Error opening %s for read\n",fname);
            return(__LINE__);
        }
        int frv=fread(fbuf,1,HPKE_MAXSIZE,fin);
        if (frv>=HPKE_MAXSIZE) {
            fprintf(stderr,"Error file %s too big\n",fname);
            return(__LINE__);
        }
        fclose(fin);
    }

    /* 
     * Find PEM encoded boundaries
     */
#define FINDLAB(buf,lab,labptr) { \
            labptr=strstr(buf,lab); \
            if (!labptr) { \
                fprintf(stderr,"Error can't find boundary (%s) in file  %s\n",lab,pfname); \
                return(__LINE__); \
            } \
        }

    char *sps=NULL;
    FINDLAB(fbuf,HPKE_START_SP,sps);
    char *spe=NULL;
    FINDLAB(sps,HPKE_END_SP,spe);
    spe--; /* there's a LF before */
    char *cts=NULL;
    FINDLAB(spe,HPKE_START_CP,cts);
    char *cte=NULL;
    FINDLAB(cts,HPKE_END_CP,cte);
    cte--; /* there's a LF before */

    /* next we gotta chew whitespace... boring, isn't it? ;-( */
    char b64buf[HPKE_MAXSIZE];
    memset(b64buf,0,HPKE_MAXSIZE);
    char *bp=b64buf;
    char *bstart=sps+strlen(HPKE_START_SP)+1;
    for (char *cp=bstart;cp<spe;cp++) {
        if (!isspace(*cp)) *bp++=*cp;
    }
    size_t paddingoctets=0;
    char *bbp=bp-1;
    while (*bbp=='=') { paddingoctets++; bbp--;}
    size_t lsplen=EVP_DecodeBlock(sp,b64buf,bp-b64buf);
    if (lsplen<=0) {
        fprintf(stderr,"Error base64 decoding sender public within file %s\n",pfname);
        return(__LINE__);
    }
    *splen=lsplen-paddingoctets;

    memset(b64buf,0,HPKE_MAXSIZE);
    bp=b64buf;
    bstart=cts+strlen(HPKE_START_CP)+1;
    for (char *cp=bstart;cp<cte;cp++) {
        if (!isspace(*cp)) *bp++=*cp;
    }
    paddingoctets=0;
    bbp=bp-1;
    while (*bbp=='=') { paddingoctets++; bbp--;}
    size_t lctlen=EVP_DecodeBlock(ct,b64buf,bp-b64buf);
    if (lctlen<=0) {
        fprintf(stderr,"Error base64 decoding ciphertezt within file %s\n",pfname);
        return(__LINE__);
    }
    *ctlen=lctlen-paddingoctets;
    return(1);
}



/*!
 * @brief hey it's main()
 */
int main(int argc, char **argv)
{
    int doing_enc=1; ///< whether we're encrypting (default) or decrypting 
    int generate=0; ///< whether we're generating a key pair (default off)
    /*
     * the xxx_in vars could be a filename or b64 value, we'll check later
     */
    char *pub_in=NULL; 
    char *priv_in=NULL;
    char *aad_in=NULL;
    char *info_in=NULL;
    char *inp_in=NULL;
    char *out_in=NULL;
#ifdef TESTVECTORS
    char *tvspec=NULL;
#endif
    char *modestr=NULL;
    char *pskid=NULL;
    char *psk_in=NULL;

    /*
     * Mode and ciphersuites - we're not parameterising this yet
     */
    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;

    int opt;

#ifdef TESTVECTORS
    while((opt = getopt(argc, argv, "?hkedvP:p:a:I:i:m:n:o:s:T:")) != -1) {
#else
    while((opt = getopt(argc, argv, "?hkedvP:p:a:I:i:m:n:o:s:")) != -1) {
#endif
        switch(opt) {
            case 'h':
            case '?': usage(argv[0],NULL); break;
            case 'v': verbose++; break;
            case 'k': generate=1; break;
            case 'e': doing_enc=1; break;
            case 'd': doing_enc=0; break;
            case 'm': modestr=optarg; break;
            case 'n': pskid=optarg; break;
            case 'P': pub_in=optarg; break;
            case 'p': priv_in=optarg; break;
            case 'a': aad_in=optarg; break;
            case 'I': info_in=optarg; break;
            case 'i': inp_in=optarg; break;
            case 'o': out_in=optarg; break;
            case 's': psk_in=optarg; break;
#ifdef TESTVECTORS
            case 'T': tvspec=optarg; break;
#endif
            default:
                usage(argv[0],"unknown arg");
        }
    }
    /*
     * barf if something obviously missing
     */
    size_t publen=0; unsigned char *pub=NULL;
    size_t privlen=0; unsigned char *priv=NULL;
    size_t aadlen=0; unsigned char *aad=NULL;
    size_t infolen=0; unsigned char *info=NULL;
    size_t plainlen=0; unsigned char *plain=NULL;
    size_t psklen=0; unsigned char *psk=NULL;

    /* check command line args */
    if (modestr!=NULL) {
        if (strlen(modestr)==strlen(HPKE_MODESTR_BASE) && 
                !strncmp(modestr,HPKE_MODESTR_BASE,strlen(HPKE_MODESTR_BASE))) {
            hpke_mode=HPKE_MODE_BASE;
        } else if (strlen(modestr)==strlen(HPKE_MODESTR_PSK) && 
                !strncmp(modestr,HPKE_MODESTR_PSK,strlen(HPKE_MODESTR_PSK))) {
            hpke_mode=HPKE_MODE_PSK;
        } else if (strlen(modestr)==strlen(HPKE_MODESTR_AUTH) && 
                !strncmp(modestr,HPKE_MODESTR_AUTH,strlen(HPKE_MODESTR_AUTH))) {
            hpke_mode=HPKE_MODE_AUTH;
        } else if (strlen(modestr)==strlen(HPKE_MODESTR_PSKAUTH) && 
                !strncmp(modestr,HPKE_MODESTR_PSKAUTH,strlen(HPKE_MODESTR_PSKAUTH))) {
            hpke_mode=HPKE_MODE_PSKAUTH;
        } else {
            usage(argv[0],"unnkown mode");
        }
    }

#ifdef TESTVECTORS
    if (tvspec!=NULL) {
        printf("Doing testvector for %s\n",tvspec);
    } else {
#endif

    /*
     * Map from command line args (or the lack thereof) to buffers
     */
    if (generate && !priv_in) usage(argv[0],"No key pair file name(s) when generating"); 

    if (!generate) { 
        if (doing_enc && !pub_in) usage(argv[0],"No recipient public key (\"-P\") provided"); 
        if (doing_enc && map_input(pub_in,&publen,&pub,1)!=1) usage(argv[0],"bad -P value");

        if (!doing_enc && !priv_in) usage(argv[0],"No recipient private key (\"-p\") provided"); 
        if (!doing_enc && map_input(priv_in,&privlen,&priv,1)!=1) usage(argv[0],"bad -p value");

        /* think again about why doing_enc is below... */
        if (doing_enc && map_input(inp_in,&plainlen,&plain,0)!=1) usage(argv[0],"bad -i value");

        if (aad_in && map_input(aad_in,&aadlen,&aad,1)!=1) usage(argv[0],"bad -a value");
        if (info_in && map_input(info_in,&infolen,&info,1)!=1) usage(argv[0],"bad -I value");
        if (psk_in && map_input(psk_in,&psklen,&psk,1)!=1) usage(argv[0],"bad -s value");
    }

#ifdef TESTVECTORS
    }
#endif

    /*
     * Init OpenSSL stuff - copied from lighttpd
     */
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS
                    |OPENSSL_INIT_LOAD_CRYPTO_STRINGS,NULL);
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS
                       |OPENSSL_INIT_ADD_ALL_DIGESTS
                       |OPENSSL_INIT_LOAD_CONFIG, NULL);

#ifdef TESTVECTORS
    /*
     * Load up and choose a testvector if asked to (and compiled
     * that way)
     * File name for this doesn't need to be parameterised yet.
     */
    char *tvfname="test-vectors.json";
    int nelems=0;
    hpke_tv_t *tvarr=NULL;
    hpke_tv_t *tv=NULL;
    if (tvspec!=NULL) {
        int trv=hpke_tv_load(tvfname,&nelems,&tvarr);
        if (trv!=1) {
            fprintf(stderr,"Can't load %s - exiting\n",tvfname);
            exit(1);
        }
        trv=hpke_tv_pick(hpke_mode,nelems,tvarr,tvspec,&tv);
        if (trv!=1) {
            fprintf(stderr,"Failed selecting test vector for %s - exiting\n",tvspec);
            exit(2);
        }
        hpke_tv_print(1,tv);
        /*
         * Assign inputs from tv - note that the strip/decode things here are not
         * exactly the same as real command line args - plaintext in particular 
         * needs to be decoded here but MUST NOT in the normal case.
         */
        if (doing_enc && map_input(tv->pkR,&publen,&pub,1)!=1) usage(argv[0],"bad -P value");
        if (!doing_enc && map_input(tv->skI,&privlen,&priv,1)!=1) usage(argv[0],"bad -p value");
        if (tv->encs && map_input(tv->encs[0].aad,&aadlen,&aad,1)!=1) usage(argv[0],"bad -a value");
        if (tv->info && map_input(tv->info,&infolen,&info,1)!=1) usage(argv[0],"bad -I value");
        if (tv->encs && map_input(tv->encs[0].plaintext,&plainlen,&plain,1)!=1) usage(argv[0],"bad -i value");

        if (hpke_mode==HPKE_MODE_PSK || hpke_mode==HPKE_MODE_PSKAUTH) {
            /*
             * grab PSK and pskID from tv 
             */
            unsigned char *dec_pskid=NULL;
            size_t dec_pskidlen=0;
            hpke_ah_decode(strlen(tv->pskID),tv->pskID,&dec_pskidlen,&dec_pskid);
            pskid=OPENSSL_malloc(strlen(tv->pskID)); /* too much but heh it's ok */
            memset(pskid,0,strlen(tv->pskID));
            memcpy(pskid,dec_pskid,strlen(tv->pskID)/2);
            OPENSSL_free(dec_pskid);
            hpke_ah_decode(strlen(tv->psk),tv->psk,&psklen,&psk);
        }
    }
#endif

    /*
     * Call one of our functions
     */
    if (generate) {
        size_t publen=HPKE_MAXSIZE; unsigned char pub[HPKE_MAXSIZE];
        size_t privlen=HPKE_MAXSIZE; unsigned char priv[HPKE_MAXSIZE];
        int rv=hpke_kg(
            hpke_mode, hpke_suite,
            &publen, pub,
            &privlen, priv);
        if (rv!=1) {
            fprintf(stderr,"Error (%d) from hpke_kg\n",rv);
            exit(1);
        }
        rv=hpkemain_write_keys(publen, pub, privlen, priv,
                priv_in,pub_in);
        if (rv!=1) {
            fprintf(stderr,"Error (%d) writing files (%s,%s)\n",rv,
                    (priv_in?priv_in:"NULL"),
                    (pub_in?pub_in:"NULL"));
            exit(1);
        }
        
    } else if (doing_enc) {
        size_t senderpublen=HPKE_MAXSIZE; unsigned char senderpub[HPKE_MAXSIZE];
        size_t cipherlen=HPKE_MAXSIZE; unsigned char cipher[HPKE_MAXSIZE];
        int rv=hpke_enc(
            hpke_mode, hpke_suite,
            pskid, psklen, psk,
            publen, pub,
            plainlen, plain,
            aadlen, aad,
            infolen, info,
            &senderpublen, senderpub,
            &cipherlen, cipher
#ifdef TESTVECTORS
            ,tv
#endif
            );
        if (pub!=NULL) OPENSSL_free(pub);
        if (plain!=NULL) OPENSSL_free(plain);
        if (info!=NULL) OPENSSL_free(info);
        if (aad!=NULL) OPENSSL_free(aad);
        if (psk!=NULL) OPENSSL_free(psk);

        if (rv!=1) {
            fprintf(stderr,"Error (%d) from hpke_enc\n",rv);
        } else {
#ifdef TESTVECTORS
            if (tv && tv->encs) {
                unsigned char *bcipher=NULL;
                size_t bcipherlen=0;
                hpke_ah_decode( strlen(tv->encs[0].ciphertext),
                            tv->encs[0].ciphertext,
                            &bcipherlen,
                            &bcipher);
                if (bcipherlen!=cipherlen) {
                    printf("Ciphertext output lengths differ: %ld vs %ld\n",
                            bcipherlen,cipherlen);
                } else if (memcmp(cipher,bcipher,cipherlen)) {
                    printf("Ciphertext outputs differ, sorry\n");
                } else {
                    printf("Ciphertext outputs the same! Yay!\n");
                }
                OPENSSL_free(bcipher);
            } else {
#endif
                int wrv=hpkemain_write_ct(out_in,senderpublen,senderpub,cipherlen,cipher);
                if (wrv!=1) {
                    return(wrv);
                }

#ifdef TESTVECTORS
            }
#endif
        }
    } else {
        /*
         * try decode and then decrypt so
         */
        size_t senderpublen=HPKE_MAXSIZE; unsigned char senderpub[HPKE_MAXSIZE];
        size_t cipherlen=HPKE_MAXSIZE; unsigned char cipher[HPKE_MAXSIZE];
        size_t clearlen=HPKE_MAXSIZE; unsigned char clear[HPKE_MAXSIZE];
        int rv=hpkemain_read_ct(inp_in,&senderpublen,senderpub,&cipherlen,cipher);
        if (rv!=1) {
            fprintf(stderr,"Error reading input - exiting\n");
            exit(rv);
        }
        rv=hpke_dec( hpke_mode, hpke_suite,
                pskid, psklen, psk,
                privlen, priv,
                senderpublen, senderpub,
                cipherlen, cipher,
                aadlen,aad,
                infolen,info,
                &clearlen, clear); 
        if (psk) OPENSSL_free(psk);
        if (priv!=NULL) OPENSSL_free(priv);
        if (info!=NULL) OPENSSL_free(info);
        if (aad!=NULL) OPENSSL_free(aad);
        if (rv!=1) {
            fprintf(stderr,"Error decrypting (%d) - exiting\n",rv);
            exit(rv);
        }

        FILE *fout=NULL;
        if (!out_in) {
            fout=stdout;
        } else {
            fout=fopen(out_in,"wb");
            if (!fout) {
                fprintf(stderr,"Decryption worked but can't open (%s) - exiting\n",out_in);
                exit(1);
            }
        }
        size_t frv=fwrite(clear,1,clearlen,fout);
        if (frv!=clearlen) {
            fprintf(stderr,"Error writing %ld bytes of output to %s (only %ld written)\n",
                        clearlen,(out_in?out_in:"STDOUT"),frv);
            exit(1);
        }
        if (out_in!=NULL) {
            fclose(fout);
            if (verbose) printf("All worked: Recovered plain is %ld octets.\n",clearlen);
        }
    } 

#ifdef TESTVECTORS
    if (tvspec!=NULL) {
        if (pskid) OPENSSL_free(pskid);
    }
    hpke_tv_free(nelems,tvarr);
#endif
    return(0);
}

