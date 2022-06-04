# Copyright 2019-201 Stephen Farrell. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# An OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
#

OSSL?=../openssl
INCL=${OSSL}/include

# NSS 
NSSL?=../dist/Debug/lib
NINCL=  -I../nss/lib \
		-I../nss/lib/nss \
		-I../nss/lib/ssl \
		-I../nss/lib/pk11wrap \
		-I../nss/lib/freebl \
		-I../nss/lib/freebl/ecl \
		-I../nss/lib/util \
		-I../nss/lib/cryptohi \
		-I../nss/lib/certdb \
		-I../nss/lib/pkcs7 \
		-I../nss/lib/smime \
		-I../dist/Debug/include/nspr

# There are test vectors for this - see comments in hpketv.h.
# If you want to compile in test vector checks then uncomment 
# the next line:
# testvectors=-D TESTVECTORS -I ../json-c

# define this if you want to use HPKE from libcrypto rather
# than from the source here
# uselibcrypto=y

CFLAGS=-g ${testvectors} -DHAPPYKEY 

CC=gcc

all: hpkemain apitest neod oeod test2evp osslplayground 

# hpke.c and hpke.h here incldue some additional tracing and test vector
# support that's not desirable in the version we'd like to see merged
# with OpenSSL - we use the unifdef tool to generate those files from
# the ones here. 
#
# If/when you make new ones of these then you need to manually move
# them over to an OpenSSL build and commit them there separately. We
# don't expect to do that often, once the HPKE PR for OpenSSL has been
# merged. If/when other developers do work on hpke.c within OpenSSL
# then, yes, this will break, but such is life.
#
# The "-x 1" below is just to get unifdef to return zero if the input
# and output differ, which should be the case for us.
forlib: hpke.c-forlib hpke.h-forlib

hpke.c-forlib: hpke.c
	- unifdef -x 1 -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke.c >hpke.c-forlib

hpke.h-forlib: hpke.h
	- unifdef -x 1 -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke.h >hpke.h-forlib

forlibclean:
	- rm -f hpke.h-forlib
	- rm -f hpke.c-forlib

copy2lib: forlib
	- cp hpke.c-forlib ${OSSL}/crypto/hpke.c
	- cp hpke.h-forlib ${INCL}/openssl/hpke.h

# This is a round-trip test with NSS encrypting and my code decrypting
# (no parameters for now)

osslplayground: osslplayground.o 
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ osslplayground.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4

osslplayground.o: osslplayground.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

neod: neod.o hpke.o neod_nss.o
	if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${OSSL}:${NSSL} ${CC} ${CFLAGS}  -g -o $@ neod.o hpke.o neod_nss.o -L ${OSSL} -lssl -lcrypto -L ${NSSL} -lnss3 -lnspr4 ; fi

neod.o: neod.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

neod_nss.o: neod_nss.c
	if [ -d ${NSSL} ]; then ${CC} -g ${CFLAGS} ${NINCL} -c $< ; fi

neodtest: neod
	- if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${OSSL}:${NSSL} ./neod ; fi

# A round-trip to test EVP mode for sender public
#
oeod: oeod.o hpke.o 
	${CC} ${CFLAGS} -g -o $@ oeod.o hpke.o -L ${OSSL} -lssl -lcrypto 

oeod.o: oeod.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

# A test of a buffer->EVP_PKEY problem

test2evp: test2evp.o 
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ test2evp.o -L ${OSSL} -lssl -lcrypto 

test2evp.o: test2evp.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<


# do a test run
test: hpkemain
	- LD_LIBRARY_PATH=${OSSL} ./hpkemain

hpke.o: hpke.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

hpkemain.o: hpkemain.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

apitest.o: apitest.c hpke.h hpke.c
	${CC} ${CFLAGS} -I ${INCL} -c $<

apitest: apitest.o hpke.o
	${CC} ${CFLAGS} -o $@ apitest.o hpke.o -L ${OSSL} -lssl -lcrypto

ifdef testvectors
hpketv.o: hpketv.c hpketv.h hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<
endif

ifdef testvectors
hpkemain: hpkemain.o hpke.o hpketv.o
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o hpketv.o -L ${OSSL} -lssl -lcrypto -L ../json-c/.libs -ljson-c
else
ifdef uselibcrypto
hpkemain: hpkemain.o
	${CC} ${CFLAGS} -o $@ hpkemain.o -L ${OSSL} -lssl -lcrypto
else
hpkemain: hpkemain.o hpke.o 
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o -L ${OSSL} -lssl -lcrypto
endif
endif

doc: hpke.c hpke.h hpketv.h hpketv.c
	doxygen hpke.doxy
	(cd doxy/latex; make; mv refman.pdf ../../hpke-api.pdf )

docclean:
	- rm -rf doxy

clean:
	- rm -f hpkemain.o hpke.o hpketv.o hpkemain 
	- rm -f neod neod.o neod_nss.o 
	- rm -f oeod oeod.o
	- rm -f osslplayground osslplayground.o
	- rm -f test2evp test2evp.o
	- rm -rf scratch/*

