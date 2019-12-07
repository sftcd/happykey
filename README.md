# happykey

This is a work-in-progress implementation of
[draft-irtf-cfrg-hpke](https://tools.ietf.org/html/draft-irtf-cfrg-hpke), using
OpenSSL, as a precursor to using that as part of the next [Encrypted SNI/ECHO
draft](https://tools.ietf.org/html/draft-ietf-tls-esni) with my [ESNI-enabled
OpenSSL](https://github.com/sftcd/openssl) fork.  (As of now, this needs to be
built against a master/tip version of OpenSSL such as my fork.)

Currently, (20191207), ``hpke_dec()`` can decrypt what ``hpke_enc()`` produces,
and valgrind seems happy for the moment, at least with nominal behaviour, so
things aren't totally shabby:-)

``hpke_enc()`` also produces output that matches the relevant CFRG test
vectors. 

I this the code now supports all ciphersuites from draft-02 of the spec, but I
still need to get the NIST curve stuff actually working ( I gotta figure out
how to combine a public key buffer and group id to make a key;-)

The default ciphersuite is x25519/hkdf-sha256/aes128gcm. To specify other
suites use "-c 3,2,1" to pick KEM number 3, KDF number 2 and AEAD number 1 from
the registry. (Yeah that's not usable, but this is just a test tool:-)

I also (seem to) support all four modes, having verified all of those against a
test vector (I needed the chacha mode for pskauth as no other test vectors
seemed to match mode 3/pskauth and my default ciphersuite - maybe that's a
message that too many options damages interop and we already have too many
options in this spec?)

Main TODOs (possibly in this order) are:
- arbitrary sizes for plain/cipher texts (640kB is a hard limit for now:-)
- APIs for non single-shot operation (non-existent:-)

## Build 

Assuming you want to build within ``$HOME/code``, as I do, then:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/happykey
            $ cd happykey

This build needs to be built against a "master" OpenSSL.  
If you want to check test vectors,
(see below) you'll also need json-c,  so my setup looks like:

- ``$HOME/code/happykey`` with this repo
- ``$HOME/code/openssl`` with a clone of [OpenSSL](https://github.com/sftcd/openssl)
- ``$HOME/code/json-c`` with a clone of [json-c](https://github.com/json-c/json-c)

If your setup differs, you'll need to hand-edit the [Makefile](Makefile)
and then:

            $ make
            gcc -g  -I ../openssl/include -c hpkemain.c
            gcc -g  -I ../openssl/include -c hpke.c
            gcc -g  -o hpkemain hpkemain.o hpke.o -L ../openssl -lssl -lcrypto

I also have a [bash script](env) that sets the environment for to pick up 
the shared objects needed:

            $ . ./env


If you do build this, ``hpkemain`` is the test tool, so start with 
``hpkemain -h`` to see what's what:

            $ ./hpkemain -h
            HPKE (draft-irtf-cfrg-hpke) tester, options are:
            Key generaion:
                Usage: ./hpkemain -k -p private [-P public] [-b]
            Encryption:
                Usage: ./hpkemain -e -P public [-p private] [-a aad] [-I info]
                        [-i input] [-o output]
                        [-m mode] [-s psk] [-n pskid] [-b]
            Decryption:
                Usage: ./hpkemain -d -p private [-P public] [-a aad] [-I info]
                        [-i input] [-o output]
                        [-m mode] [-s psk] [-n pskid] [-b]
            This version is built with TESTVECTORS
                Usage: ./hpkemain -T [-m mode] [-b]
            Options:
                -a additional authenticated data file name or actual value
                -b use backup ciphersuite
                -d decrypt
                -e encrypt
                -h help
                -I additional info to bind to key - file name or actual value
                -i input file name or actual value (stdin if not specified)
                -k generate key pair
                -P public key file name or base64 or ascii-hex encoded value
                -p private key file name or base64 or ascii-hex encoded value
                -m mode (one of: base,psk,auth or pskauth)
                -n PSK id string
                -o output file name (output to stdout if not specified) 
                -s psk file name or base64 or ascii-hex encoded value
                -T run a testvector for mode/suite
                -v verbose output

            Notes:
            - Sometimes base64 or ascii-hex decoding might work when you
              don't want it to (sorry about that;-)
            - If a PSK mode is used, both pskid "-n" and psk "-s" MUST
              be supplied
            - For auth or pskauth modes, provide both public and private keys
            - Default ciphersuite is x25519/sha256/aeg128gdm to use the
              backup ciphersuite of x448/sha512/chacha20-poly1305 use "-b"

There's a bit of (unfinished) doxygen-generated documentation of the [API](hpke-api.pdf).

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

(Not sure that PEM-like stuff is wise, but we'll see - it's good enough
to let me easily test round-tripping at least.)

The [roundtrip.sh](roundtrip.sh) script fetches some plaintext, generates a key
pair, encrypts a file to that public key, then decrypts that. All relevant
files end up in ``$HOME/code/happykey/scratch`` with random looking names. (A 
``make clean`` will clean those out too.)

The [infoaadtest.sh](infoaadtest.sh) script does the same as
[roundtrip.sh](roundtrip.sh) but provides optional (random) AAD and Info inputs
to encryption and checks that decryption works or fails as appropriate when
good/bad values are provided.  The [modetest.sh](modetest.sh) script is like
[infoaadtest.sh](infoaadtest.sh) but goes through all the modes, with good and
bad PSK and PSKID values.  For both scripts, you can add extra comnand line
parameters (e.g. "-c 1,1,1") and those'll be passed on to the key generation
and encrypt/decrypt calls.

The [tvtest.sh](tvtest.sh) script tests all cipheruite options (but not
yet modes), against test vectors...

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
 
The authors of the HPKE draft also published some (96!) test vectors,
so one of the things I did while coding was to check I get the same
values as those.

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
one that matches my chosen mode/suite, then print out various intermediate values on
the way to checking the ciphertext from ``hpke_enc()`` matches the test
vector... and that now works.  (That means ``-T thing`` is the same for all
values of "thing" for now - will add code for selecting stuff later when I get
other ciphersuites done.)

So far, it appears that there is only one test vector matching each
of my supported modes and ciphersuites. So we're not gonna do much
better than just picking the first:-)


