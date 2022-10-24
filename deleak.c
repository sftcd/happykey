/* de-leak a thing */

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/ech.h>

int main(int argc, char **argv) 
{
    SSL_CONF_CTX *cctx = NULL;
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *meth = TLS_server_method();
    char *echkeyfile = "/home/stephen/code/openssl/esnistuff/echconfig.pem";
    // char *echkeyfile = "/home/stephen/code/openssl/esnistuff/echkeydir/d13.pem";
    // char *echkeyfile = "/home/stephen/code/openssl/esnistuff/echkeydir/dext.pem";
    char *echdir = "/home/stephen/code/openssl/esnistuff/echkeydir";
    int nloaded = 0;

    if (argc == 2) {
        echkeyfile = argv[1];
    }

    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        printf("Failed to init ctx - exiting\n");
        return 0;
    }

    if (SSL_CTX_ech_server_enable(ctx,echkeyfile) != 1) {
        printf("Failed to load: %s\n",echkeyfile);
    } else {
        printf("Loaded: %s\n",echkeyfile);
    }

    if (SSL_CTX_ech_readpemdir(ctx,echdir,&nloaded) != 1 ) {
        printf("Failed to read dir: %s\n",echdir);
    } else {
        printf("Read dir: %s\n",echdir);
    }

    SSL_CTX_free(ctx);

    return 1;
}


