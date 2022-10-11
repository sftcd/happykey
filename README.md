# happykey

This is an implementation of [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html), 
using OpenSSL, as a precursor to using that for 
[Encrypted SNI/ECH](https://tools.ietf.org/html/draft-ietf-tls-esni) with my 
[ECH-enabled OpenSSL fork](https://github.com/sftcd/openssl).  This needs to be built
against a master/tip version of OpenSSL such as my fork.

I've submitted a [pull request](https://github.com/openssl/openssl/pull/17172)
for inclusion of HPKE in OpenSSL, based on this code. Since that'll take a
while to happen, and then turn up in an official OpenSSL release, the idea is
that applications can use this as a sort of "polyfill" (borrowing the 
[concept](https://en.wikipedia.org/wiki/Polyfill_(programming) used in web 
development:-) in the meantime. I also plan to update this as newer
HPKE ciphersuites are defined but that code won't (at least initially)
be part of the OpenSSL PR.

High level notes:

- All 480 local tests (``./alltest.sh``) are working - yes, you get to
  480 test combinations with the variations allowed. That's too many IMO.
- For test vectors, see ``tvtest.sh`` output - 96 tests pass, 
  and 84 don't match a test vector. 
- The default ciphersuite is x25519/hkdf-sha256,hkdf-sha256,aes128gcm. 
- (Almost) Only the single-shot APIs are supported.
- Exporters are not supported.

## Recent Changes

- 20221011: more changes based on PR comments, incl. export-only
  mode and tests

- 20221010: more changes based on PR comments

- 20221008: changes to str2suite based on PR comments

- 20221007: changes to keep OpenSSL CI happy

- 20221006: getting PR comments on this now...
    - DHKEM apis handle 9180 det key gen so I could lose that code

- 20221005: reduced HPKE code duplication when building with DHKEM 
  PR now having being merged (but keeping ability to build and link to
  a released OpenSSL 3.0.0). TODO: ECH checks.

- 20220928: now working on two build targets - one for when using
  the system install of OpenSSL (3.0 or above) (using -DHAPPOBJS),
  so HPKE API objects need to be directly linked to application code,
  and a second for when linking with a master branch build that has
  the new HPKE APIs built-in (-DHPKEAPI).  The ``make forlib`` and
  ``make copy2lib`` targets can be used to create and move the
  relevant files (``hpke.h, hpke.c`` and ``apitest.c`` with some
  ifdef'd code taken out using the ``uninfdef`` tool) to an OpenSSL build.

- 202200906: new API seal/open working, with export APIs, and more
  test vectors, ECH interop tested

- 20220828: made quite a few changes based on review of our 
  [OpenSSL HPKE PR](https://github.com/openssl/openssl/pull/17172). Many
  fairly trivial, but one required adding a shim for the otherwise
  internal ``WPAKCET_*()`` APIs.

- 20220618: added a (possibly temporary, possibly not) proposal for
  a higher level API that better matches the RFC text - idea is to
  see if OpenSSL devs prefer that (or something derived from that).
  If so, will implement it then:-)

- 20220716: replace ``ossl_hpke_suite_st`` with ``OSSL_HPKE_SUITE``
  as per OpenSSL dev guidance.

- 20220714: added HPKE deterministic key generation - had
  previously omitted that as it wasn't needed for ECH but as it will be
  needed for MLS and maybe other HPKE consumers, it was time to add it

- 20220711: a pile of changes (including some external names) based on 
  fine comments received from OpenSSL developers)

- 20220610: improved the doxygen documentation some - the [PDF](hpke-api.pdf)
  should now actually be useful:-)

- 20220610: many tweaks to make the OpenSSL ``util/check-format.pl`` script
  happy with the code that's intended for inclusion inside the library

- 20220608: expanded apitest.c significantly, and integrated that into
  the OpenSSL ``make test`` target which resulted in some internal
  changes due to evolution of upstream APIs (and a pair of bug fixes
  which is nice)

- 20220604: added [``apitest.c``](apitest.c) which'll be moved into
  openssl ``make test`` target (probably ``test/evp_extra_test.c``
  as currently or maybe elsewhere)

- 20220604: changed internal aead, kem and kdf tables to be packed
  rather than sparse - that'll be better if/as larger IANA codepoints
  are allocated

- 20220603: changes to external API names e.g. from ``hpke_enc``
  to ``OSSL_HPKE_enc`` for consistency with OpenSSL conventions.
  Various other similar changes.

- 20220602: A number of changes taking the "polyfill" approach and
  reacting to comments on the PR we've submitted for the OpenSSL library.
  (I've only partly handled those comments so far.)

- 20220530: Added instructions for building with an OpenSSL that 
  includes HPKE (from my fork) and rebasing, 'cause I always forget ;em;-)

- 20220225: HPKE is now [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html),
  so various comments updated accordingly.

- 20211215: added a sketch of a [higher level API](hpkehigh.h) that
  could be developed as part of discussion of PR for upstream. My
  current working hypothesis is that that'd be a bad plan. 

- 20211205: Changed to use ``EVP_KDF_*`` APIs for extract/expand instead 
  of ``EVP_PKEY_derive*`` as advised by OpenSSL upstream maintainer. 

- 20211204: many teeny cosmetic changes to better match OpenSSL code
  style. (One interesting change to return explicit non-zero error values
  from hpkemain - one of our __LINE__ error returns was on line 512 and
  when tha percolated out to the shell as the parameter to an ``exit()``
  call it was of course seen as zero - confusing my test scripts into
  seeing an unexpectd success when a failed decryption was the nominal
  text extpection!)

- 20211129: Fixed some issues that became apparent as I was documenting
  HPKE for an OpenSSL PR - mostly just parameter name changes but one
  real change was to allow an ``EVP_PKEY*`` form for the private key
  for authentication in ``hpke_enc()`` 

- 20211128: added ossplayground.c as a place play with code to be
  added to OpenSSL ``make test`` target.

- 20211127: minor tweak as I documented things to prepare a PR 
  for OpenSSL.

- 20211104: Added ``hpke_setlibctx()`` API to allow caller to set
  a new default ``OSSL_LIB_CTX`` - that's needed for the OpenSSL
  ``make test`` target that makes use of such.

- 20211030: added ``HPKE_DEFSIZE`` (40kB) for handling e.g. stdin 
  when we don't know plaintext/ciphertext buffer size and reduced 
  the value of ``HPKE_MAXSIZE`` to 2kB as that's now only used 
  for keys and internal buffers that won't be that big until we hit
  PQC or something (which is not now:-). 

- 20211029: removed size restriction on plaintext and ciphertext
  (keys and other structures are still internallhy stack-based 
  and limited to ``HPKE_MAXSIZE``).

- 20211012: fixed doube-free if bad value fed to NIST decoding of
  public key buffer

- 20210903: doing interop testing with boringssl, TLS HRR handing
  requires use of the same HPKE context twice, which in turn
  implies incrementing the nonce, so we added a sequence input
  to ``hpke_enc()`` and ``hpke_dec()`` and co. HRR handing
  isn't yet working, but this change moves us along a bit it
  seems. (However, more change here may also be needed, we'll
  have to see.) This also generates a TODO: - to add some 2nd
  encryptions to the test vector tests - we'll get back to that
  once get we interop for HRR cases.

- 20210823: more cosmetic stuff - get rid of spaces at end of
  lines (also for OpenSSL style points apparently;-)

- 20210816: a pile of cosmetic checks to stick to 80-char line
  lengths (for OpenSSL style points:-)

- 20210816: added ``hpke_expansion`` allowing caller to know the
  ciphertext length, they'll see for a given plaintext length 
  (basically 16 more octets for an aead tag:-) which is needed
  for ECH draft-13.

- 20210310: Surprisingly easy update to draft-08 and the (hopefully)
final test vectors and version label. The Makefile defines the "DRAFT_08"
symbol which causes the runtime to use the "HPKE-v1" label and to
use the ``test-vectors-08.json`` file. If that's not defined then
the "HPKE-07" label will be used instead. (Note to self: once 
Cloudflare and/or NSS have upgraded to draft-10 of ECH/draft-08 of
HPKE then I'll change the default. That'll hopefully be soon.)

- 20210310: tidied up hpke.c and esp ``hpke_buf2evp``

- 20210310: added test2evp.c to see if we can unify the buffer to
``EVP_PKEY`` code for NIST and non-NIST curves. Got some help on
openssl-users list for that from Matt Caswell which sorted it out.

- 20210309: Still needs tidying but I've gotten rid of the deprecation
warnings finally. So this is just an overnight checkpoint before I
tidy that up.

- 20210305: Added external API to map from buffer & kem-id to private
key.

- 20210304: built against rebased upstream openssl - there are some
deprecations still to handle, but otherwise happkeys is ok

- 20210301: fixed the ``hpke_enc_evp`` variant

- 20210220: improvement/fix inside ``hpke_expand`` - was assuming desired
output length and available buffer size (as input) were the same which is
not always the case.

- 20210220: Added a test (see ``neod.c``,``neod_nss.c``) to try a round-trip
  case where a long term key pair is generated by happykey, then NSS is used to
encrypt to that public key, and finally we try a decrypt with happykey. That
round-trip works ok in a basic test, (had some issues with test-code
initially), so the fact that ECH from NSS to my openssl build is currently
failing should be due to some protocol level thing and not something wrong
inside HPKE, which should be good.... Aargh (and face palm;-) - turned out I
was compiling in draft-06 labels in the openssl build of hpke. 

- 20201216: Updated for draft-07, only changes made is the new
labels, and disable support for draft-05 - still haven't added exporter stuff.

- 20201204: Made an internal api external (``hpke_suite_check()``) to allow a
  client to check if the suite presented e.g. from an ECHConfig is supported
locally.

- 20201027: this implements HPKE draft-06 as the default. It also supports HPKE
  draft-05 with the X-coordinate DH fix.  This code verifies the most recently
posted [test vectors](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json)
for draft-06. (Or the older ones for draft-05.) 
As we also (currently, hopefully briefly) need to keep draft-05 code too, because
that's apparently what the latest ESNI/ECH draft requires (sheesh!),
I've kept both. See the [Makefile](Makefile) for how to define
the right things (hint: ``-DDRAFT_06`` is one way:-).

## Build 

Assuming you want to build within ``$HOME/code``, with the upstream
OpenSSL library, as I usually do, then:

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

## Build with OpenSSL that includes HPKE

I have an OpenSSL fork with a [branch](https://github.com/sftcd/openssl/tree/HPKE-PR) 
that has HPKE built into the library. (And a related [PR](https://github.com/openssl/openssl/pull/17172)
for inclusion of that with upstream. If you want to build with that then
instead of the above you want:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl.git
            $ cd openssl
            $ git checkout HPKE-PR
            $ ./config  
            $ make -j8

Then you need to modify the Makefile for happykey:

            $ cd $HOME/code/happykey
            $ vi Makefile
            # uncomment the line for uselibcrypto=y
            $ make
            $ ./alltest.sh
            All done. All good. (480 tests)

## Rebasing the OpenSSL that includes HPKE

Upstream code changes all the time and I always forget how to
catch up with that properly. (And probably do it wrong in any
case;-) Doing this obvious requires you to have write access
to the origin, so this note is mostly for me:-)

Here's how I'm currently doing that and plan to in
future:

            $ cd $HOME/code
            $ git clone git@github.com:sftcd/openssl.git openssl-rebase
            $ cd openssl-rebase
            $ git remote add upstream https://github.com/openssl/openssl.git
            $ git fetch upstream
            $ git checkout master
            $ git reset --hard upstream/master
            $ git push origin master --force 

That gets the ``master`` branch up to date with upstream. Next is to rebase
my own branch(es) with that, e.g. for HPKE-PR.

            $ git checkout HPKE-PR
            $ git rebase master HPKE-PR

That last has needs some repetitive stuff but works in the end
but don't forget to build/test/push to origin too.

            $ make clean
            $ ./config
            $ make -j8
            $ make test
            $ git push

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
[test-vectors-08](test-vectors-08.json) 
from 
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

