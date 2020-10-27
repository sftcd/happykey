# happykey

This is a work-in-progress implementation of
[draft-irtf-cfrg-hpke](https://tools.ietf.org/html/draft-irtf-cfrg-hpke), using
OpenSSL, as a precursor to using that as part of the next [Encrypted SNI/ECH
draft](https://tools.ietf.org/html/draft-ietf-tls-esni) with my [ESNI-enabled
OpenSSL](https://github.com/sftcd/openssl) fork.  This needs to be
built against a master/tip version of OpenSSL such as my fork.

The current (20201027) status is that the implements HPKE draft-06 as
the default. It also supports 
HPKE draft-05 with
the X-coordinate DH fix. 
This code verifies the most recently posted 
[test vectors](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json)
for draft-06. (Or the older ones for draft-05.) 

As we also (currently, hopefully briefly) need to keep draft-05 code too, because
that's apparently what the latest ESNI/ECH draft requires (sheesh!),
I've kept both. See the [Makefile](Makefile) for how to define
the right things (hint: ``-DDRAFT_06`` is one way:-).

High level notes:

- All 480 local tests (``./alltest.sh``) are working - yes, you get to
  480 test combinations with the variations allowed. That's too many IMO.
- For test vectors, see ``tvtest.sh`` output - 96 tests pass, 
  and 84 don't match a test vector. 
- The default ciphersuite is x25519/hkdf-sha256,hkdf-sha256,aes128gcm. 
- Only the single-shot APIs are supported.
- Exporters are not supported.
- There is a limit of 40KB on the buffers supported, including plain 
  and ciphertexts.

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

I also have a [bash script](env) that sets the environment vars to pick up 
the shared objects needed:

            $ . ./env


If you do build this, ``hpkemain`` is the test tool, so start with 
``hpkemain -h`` to see what's what:

            $ ./hpkemain -h
            HPKE (draft-irtf-cfrg-hpke) tester, options are:
            Key generaion:
                Usage: ./hpkemain -k -p private [-P public] [-c suite]
            Encryption:
                Usage: ./hpkemain -e -P public [-p private] [-a aad] [-I info]
                        [-i input] [-o output]
                        [-m mode] [-c suite] [-s psk] [-n pskid]
            Decryption:
                Usage: ./hpkemain -d -p private [-P public] [-a aad] [-I info]
                        [-i input] [-o output]
                        [-m mode] [-c suite] [-s psk] [-n pskid]
            Options:
                -a additional authenticated data file name or actual value
                -c specify ciphersuite
                -d decrypt
                -e encrypt
                -h help
                -I additional info to bind to key - file name or actual value
                -i input file name or actual value (stdin if not specified)
                -k generate key pair
                -P public key file name or base64 or ascii-hex encoded value
                -p private key file name or base64 or ascii-hex encoded value
                -m mode (a number or one of: base,psk,auth or pskauth)
                -n PSK id string
                -o output file name (output to stdout if not specified) 
                -s psk file name or base64 or ascii-hex encoded value
                -v verbose output

            Notes:
            - Sometimes base64 or ascii-hex decoding might work when you
              don't want it to (sorry about that;-)
            - If a PSK mode is used, both pskid "-n" and psk "-s" MUST
              be supplied
            - For auth or pskauth modes, provide both public and private keys
            - Ciphersuites are specified using a comma-separated list of numbers
              e.g. "-c 0x20,1,3" or a comma-separated list of strings from:
                  KEMs: p256, p384, p521, x25519 or x448
                  KDFs: hkdf-sha256, hkdf-sha384 or hkdf-sha512
                  AEADs: aes128gcm, aes256gcm or chachapoly1305
              For example "-c x25519,hkdf-sha256,aes128gcm" (the default)

There's a bit of (unfinished) doxygen-generated documentation of the [API](hpke-api.pdf).

## PEM-like ciphertext file format

Since we need the ciphertext and sender's public key to do a decrypt,
the ``hpkemain`` command line test tool saves both of those in one
file. An [example](PEM-like-sample) of one of those is included:

            $ cat PEM-like-sample
            -----BEGIN SENDERPUB-----
            Oxsee6j2HJ5v00nfO3oOxwszKT25d4uiR2Aga+HPKAI=
            -----END SENDERPUB-----
            -----BEGIN CIPHERTEXT-----
            MPMS0EjIPJ2hRlJH8J9WLLlU2cPnWlmw6FyS1uxI6xyBx4nwWPGNCSZxQ65JP5xNYDqwKtTGTK5IR4nrs2ZqK4zTEROohDCtciUmB2A8+VBu1w==
            -----END CIPHERTEXT-----

My code for reading those files is a little (but not a lot:-) tolerant, e.g. it
allows additional whitespace to be added within the base64 encoded values.
I'm not sure if that PEM-like stuff is wise, but we'll see - it's good enough
to let me easily test round-tripping at least.

## Encrypt a file

There's a file with a sample [public key](pub) to which you can encrypt things.
(I don't have the private key, honest:-) Using that to enrypt the tiny shell
script [env](./env), looks like this:

            $ ./hpkemain -P pub -i env
            -----BEGIN SENDERPUB-----
            AhsDyKTnsE+W42q+c3fiXX7F/WgZqTMBSMHKiYd5xnE=
            -----END SENDERPUB-----
            -----BEGIN CIPHERTEXT-----
            IcUIJv4YCX57Uh/cH+KQCMCErLFQtXQgsk68lsCubUCzAVtEH7X1/eqhsij7ly0M9Mozp+r+7tp7s1hoFHtdI52G9frDnDjQ3OG+P0bpMJ7ovA==
            -----END CIPHERTEXT-----

## Test scripts

The [tvtest.sh](tvtest.sh) script tests all combinations of mode/cipheruite
against test vectors.
That currently shows 84 cases (out of 180) where there is no match in the
set of test vectors.

The [alltest.sh](alltest.sh) script tests key generation, encryption,
decryption and failed decryption, for all combinations of mode/cipheruite. 
Failed decryption tests for some
expected failed decryptions (e.g. presenting bad PSK values).  All relevant
files end up in ``$HOME/code/happykey/scratch`` with random looking names. (A
``make clean`` will clean those out too.)

The [roundtrip.sh](roundtrip.sh) script fetches some plaintext, generates a key
pair, encrypts a file to that public key, then tries to decrypt that.  You can
add extra comnand line parameters (e.g. "-c 0x20,1,1") and those'll be passed on
to the key generation and encrypt/decrypt calls.

The [infoaadtest.sh](infoaadtest.sh) script does the same as
[roundtrip.sh](roundtrip.sh) but provides (random) AAD and Info inputs to
encryption and checks that decryption works or fails as appropriate when
good/bad values are provided. That's only done for base and psk modes for now.
As before, you can add extra comnand line parameters (e.g. "-c 0x20,1,1") and
those'll be passed on to the key generation and encrypt/decrypt calls.

## Key generation

To generate a key pair and store the private key in PEM format (PKCS#8 PrivateKey)
and the public key as a binary value:

            $ ./hpkemain -k -p privfile -P pubfile
            $ hd pubfile 
            00000000  84 16 89 b8 1c 16 ac 40  1a 7e 3d df f1 5b 38 fd  |.......@.~=..[8.|
            00000010  29 6d e7 cc f4 47 5d 64  c3 d8 b0 70 21 39 70 7f  |)m...G]d...p!9p.|
            00000020
            $ cat privfile 
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEIDDuKfoFZyFu9Xh1m0HKbkbC6F5HXZed+dYwx5YDQyp8
            -----END PRIVATE KEY-----

Or you can put both keys in one file if you omit the public key file name:

            $ ./hpkemain -k -p both
            $ cat both
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEINDTadwuLL44s9CU994pqowjI/rS1Vqg8Ate0dblQOtW
            -----END PRIVATE KEY-----
            -----BEGIN PUBLIC KEY-----
            qfmyAu9tcQM8MQtg1pWimIz9gdAwXZDUzWPbm4Y5/Wg=
            -----END PUBLIC KEY-----

## Test Vectors
 
The authors of the HPKE draft also published a pile of test vectors,
so one of the things I did while coding was to check I get the same
values as those when encrypting with the given keys.

To enable test vector checking, compile with ``TESTVECTORS`` #define'd.
There's a line to uncomment in the [Makefile](Makefile) that does that.
To do the test vector comparison I use the published 
[test-vectors-06](test-vectors-06.json) or [test-vectors-05](test-vectors-05.json),
as appropriate, from 
[the CFRG repo](https://github.com/cfrg/draft-irtf-cfrg-hpke).  I use the 
[json-c](https://github.com/json-c/json-c) library to decode
the JSON file into an array of type``hpke_tv_t`` that I defined.
The [Makefile](Makefile) here assumes that you've built json-c in a sibling
directory to this one as shown above.

As of now, when the ``-T`` commnand line argument is used, the JSON file of
test vectors is loaded into an array of ``hpke_tv_t`` and I just pick the first
one that matches my chosen mode/suite, then print out various intermediate values on
the way to checking the ciphertext from ``hpke_enc()`` matches the test
vector... and that now works.  

It appears that there is only one test vector matching each
of my supported modes and ciphersuites. So we're not gonna do much
better than just picking the first match:-)

When you turn on ``TESTVECTORS`` then a pile of extra tracing is done
to stdout. More or less the same happens if you ``#defined SUPERVERBOSE``
in [hpke.c](hpke.c). As that's not really "proper" logging, and would
expose key material, both are off by default. But that should be a
reminder that this is intended for test and not for real-world uses.
(I plan to incorporate code from this into my OpenSSL fork when that's
offered to upstream for ESNI/ECH.)

