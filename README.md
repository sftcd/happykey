# happykey

I'm implementing
[draft-irtf-cfrg-hpke](https://tools.ietf.org/html/draft-irtf-cfrg-hpke) using
OpenSSL, as a precursor to using that as part of the next [Encrypted SNI/ECHO
draft](https://tools.ietf.org/html/draft-ietf-tls-esni) with my [ESNI-enabled
OpenSSL](https://github.com/sftcd/openssl) fork.

Note: Lotsa work remains!

Currently, (20191201) ``hpke_enc()`` produces an output, and one that
matches a CFRG test vector, but lots is hard-coded to one ciphersuite
(x25519,hkdf-sha256,aes128gcm) and plenty of code needs re-factoring. 

``hpke_dec()`` can now also decrypt what ``hpke_enc()`` produced, so
that's also good:-)

## Build 

You'll probably want to start by cloning this, I'll assume you do that
from within ``$HOME/code``, e.g.:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/happykey
            $ cd happykey

The build needs OpenSSL.  (Not sure if I'm using anything that needs building
from the OpenSSL tip, but I'll check that.) If you want test vectors, (see
below) you'll also need json-c,  so my setup looks like:

- $HOME/code/happykey with this repo
- $HOME/code/openssl with a clone of https://github.com/sftcd/openssl
- $HOME/code/json-c with a clone of https://github.com/json-c/json-c

If your setup differs, you'll need to hand-edit the [Makefile](Makefile)
and then:

            $ make
            gcc -g  -I ../openssl/include -c hpkemain.c
            gcc -g  -I ../openssl/include -c hpke.c
            gcc -g  -o hpkemain hpkemain.o hpke.o -L ../openssl -lssl -lcrypto

I also have a [bash script](env) that sets the environment for those shared objects:

            $ . ./env


If you build this, start with ``hpkemain -h`` to see what's what.

            $ ./hpkemain -h
            Usage: ./hpkemain [-h|-v|-k|-e|-d] [-P public] [-p private] [-a aad] [-I info] [-i input] [-o output]
            HPKE (draft-irtf-cfrg-hpke) tester, options are:
	            -h help
	            -v verbose output
	            -e encrypt
	            -d decrypt
	            -k generate key pair
	            -P public key file name or base64 or ascii-hex encoded value
	            -p private key file name or base64 or ascii-hex encoded value
	            -a additional authenticated data file name or actual value
	            -I additional info to bind to key - file name or actual value
	            -i input file name or actual value (stdin if not specified)
	            -o output file name (output to stdout if not specified) 
            
            note that sometimes base64 or ascii-hex decoding might work when you don't want it to
            (sorry about that;-)
            
            When generating a key pair, supply public and private file names

There's a bit of (unfinished) doxygen-generated documentation of the [API](hpke-api.pdf).

## Encrypt a file

There's a file with a sample [public key](pub) to which you can encrypt things.
(I don't have the private key, honest:-) Using that to enrypt the tiny shell
script [env](./env), looks like this:

            $ ./hpkemain -P pub -i env
            -----BEGIN SENDERPUB-----
            zr3hth4TdmxbZk8hyM1ScIfBbHDq3EqOJ+lJ+PowgA8=
            -----END SENDERPUB-----
            -----BEGIN CIPHERTEXT-----
            lwmIl7EpoPbZy3UQBM5B8gBNICHqfuNGwvkraWxFMPfOcPlH19ifEz2Qch6WLFeGGY4C5MtkbJv6A2/kJqTGOSQ7nwWZKXSgTG2wGXpXyZHN2Q==
            -----END CIPHERTEXT-----

(Not sure that MIME type like stuff is wise, but we'll see - it'll be good enough
to let me easily test round-tripping at least.)

The [roundtrip.sh](roundtrip.sh) script fetches some plaintext, generates a key
pair, then encrypts a file to that public key, then decrypts that. All relevant
files end up in ``$HOME/code/happykey/scratch`` with random looking names. (A 
``make clean`` will clean those out too.)

## PEM-like ciphertext file format

Since we need the ciphertext and sender's public key to do a decrypt,
the ``hpkemain`` command line test tool saves both of those in one
file. An [example](PEM-like-sample) of one of those might be:

            $ ./hpkemain -P pub -i env -o PEM-like-sample
            $ cat PEM-like-sample
            -----BEGIN SENDERPUB-----
            4LQhEvh+EeipiyHVYxHzbX73KqqTnMdRj08kVrceJXw=
            -----END SENDERPUB-----
            -----BEGIN CIPHERTEXT-----
            oTU3z+2R2no0elqYm5N2l0H+HuI0d7wp6w20k1JMD+MZ8US//egDjU1oKByGBFbSH7AoEbe9OY7zhUExVKJnhVl0FwAL5txBPpNbwt4sgT/dpg==
            -----END CIPHERTEXT-----

My code for reading those files is a little (but not a lot:-) tolerant, e.g. it
allows additional whitespace to be added within the base64 encoded values.

## Key generation

To generate a key pair and store the private key in PEM format (PKCS#8 PrivateKey)
and the public key as a binary value:

            $ ./hpkemain -k -p privfile -P pubfile
            $ cat privfile
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEIIArh+i/Cp1kResmsimUskHPp0yUxoKj4oklv11t9NhJ
            -----END PRIVATE KEY-----
            $ hd pubfile 
            00000000  f1 8e e3 9f 90 4f 73 47  eb 60 81 4a 41 76 40 72  |.....OsG.`.JAv@r|
            00000010  87 3e 51 28 0c 9f d2 34  a9 c6 7c c8 68 4f 71 38  |.>Q(...4..|.hOq8|
            00000020

Or you can put both keys in one file if you omit the public key file name:

            $ ./hpkemain -k -p both
            $ cat both
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEIChYQexI/NDGRL1T01Ym4lyLUxT75GMgoVIalV+Va5pU
            -----END PRIVATE KEY-----
            -----BEGIN PUBLIC KEY-----
            b/OkZZ/VNEs+H3NrHpb+F0nYeagcV2knkCZ0BOtaX3M=
            -----END PUBLIC KEY-----

## Test Vectors
 
To enable test vector checking, compile with ``TESTVECTORS`` #define'd.
There's a line to uncomment in the [Makefile](Makefile) that does that.
To do the test vector comparison I use the published 
[test-vectors](test-vectors.json) from 
[the CFRG repo](https://github.com/cfrg/draft-irtf-cfrg-hpke).  I use the 
[json-c](https://github.com/json-c/json-c) library to decode
the JSON file into an array of type``hpke_tv_t`` that I defined.
The [Makefile](Makefile) here assumes that you've built json-c in a sibling
directory to this one as shown above.

As of now, when the ``-T`` commnand line argument is used, the JSON file of
test vectors is loaded into an array of ``hpke_tv_t`` and I just pick the first
one that matches my chosen suite, then print out various intermediate values on
the way to checking the ciphertext from ``hpke_enc()`` matches the test
vector... and that now works.  (That means ``-T thing`` is the same for all
values of "thing" for now - will add code for selecting stuff later when I get
other ciphersuites done.)


