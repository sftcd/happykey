# happykey

I'm implementing
[draft-irtf-cfrg-hpke](https://tools.ietf.org/html/draft-irtf-cfrg-hpke) using
OpenSSL, as a precursor to using if as part of the next [Encrypted SNI/ECHO
draft](https://tools.ietf.org/html/draft-ietf-tls-esni) with my [ESNI-enabled
OpenSSL](https://github.com/sftcd/openssl) fork.

Note: Lotsa work remains!

Currently, (20191129) ``hpke_enc()`` produces an output, and one that
matches a CFRG test vector, but lots is hard-coded to one ciphersuite
(x25519,hkdf-sha256,aes128gcm) and plenty of code needs re-factoring. 

...and ``hpke_dec()`` is still just a stub:-)

If you build this, start with ``hpkemain -h`` to see what's what.

            $ ./hpkemain -h
            Usage: ./hpkemain [-h|-v|-e|-d] [-P public] [-p private] [-a aad] [-I info] [-i input] [-o output] [-T tvspec]
            HPKE (draft-irtf-cfrg-hpke) tester, options are:
                -h help
                -v verbose output
                -e encrypt
                -d decrypt
                -P public key file name or base64 or ascii-hex encoded value
                -p private key file name or base64 or ascii-hex encoded value
                -a additional authenticated data file name or actual value
                -I additional info to bind to key - file name or actual value
                -i input file name or actual value (stdin if not specified)
                -o output file name (output to stdout if not specified) 
                -T run a testvector for mode/suite, e.g. "-T 0,1,1,2"
            
            note that sometimes base64 or ascii-hex decoding might work when you don't want it to
            (sorry about that;-)
            This version is built with TESTVECTORS
            You should either choose "normal" inputs or use "-T" not both.


## Test Vectors
 
To enable test vector checking, compile with ``TESTVECTORS`` #define'd.
There's a line to uncomment in the [Makefile](Makefile) that does that.

To do that test vector comparison I use the published 
[test-vectors](test-vectors.json) from 
[the CFRG repo](https://github.com/cfrg/draft-irtf-cfrg-hpke).  
I use the [json-c](https://github.com/json-c/json-c) library to decode
the JSON file into an array of type``hpke_tv_t`` that I defined.
The [Makefile](Makefile) here assumes that you've build json-c in a sibling
directory to this one.

As of now, when the ``-T`` commnand line argument is used, the JSON file of
test vectors is loaded into an array of ``hpke_tv_t`` and I just pick the first
one that matches my chosen suite, then print out various intermediate values on
the way to checking the ciphertext from ``hpke_enc()`` matches the test
vector... and that now works.  (That means ``-T thing`` is the same for all
values of "thing" for now - will add code for selecting stuff later when I get
other ciphersuites done.)

## Build Directories

My setup looks like:

- $HOME/code/happykey with this repo
- $HOME/code/openssl with a clone of https://github.com/sftcd/openssl
- $HOME/code/json-c with a clone of https://github.com/json-c/json-c

I also have a [bash setup](env) for those shared objects:

            $ . ./env

Not sure if I'm using anything that needs building from the OpenSSL
tip, but can check that.

