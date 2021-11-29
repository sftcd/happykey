# Copyright 2019-201 Stephen Farrell. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# An OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
#

OSSL=../openssl
INCL=../openssl/include

# NSS 
NSSL=../dist/Debug/lib
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

CFLAGS=-g ${testvectors} -DHAPPYKEY 

CC=gcc

all: hpkemain neod oeod test2evp osslplayground

# This is a round-trip test with NSS encrypting and my code decrypting
# (no parameters for now)

osslplayground: osslplayground.o 
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ osslplayground.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4

osslplayground.o: osslplayground.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

neod: neod.o hpke.o neod_nss.o
	LD_LIBRARY_PATH=${OSSL}:${NSSL} ${CC} ${CFLAGS}  -g -o $@ neod.o hpke.o neod_nss.o -L ${OSSL} -lssl -lcrypto -L ${NSSL} -lnss3 -lnspr4

neod.o: neod.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

neod_nss.o: neod_nss.c
	${CC} -g ${CFLAGS} ${NINCL} -c $<

neodtest: neod
	- LD_LIBRARY_PATH=${OSSL}:${NSSL} ./neod

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

ifdef testvectors
hpketv.o: hpketv.c hpketv.h hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<
endif

ifdef testvectors
hpkemain: hpkemain.o hpke.o hpketv.o
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o hpketv.o -L ${OSSL} -lssl -lcrypto -L ../json-c/.libs -ljson-c
else
hpkemain: hpkemain.o hpke.o 
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o -L ${OSSL} -lssl -lcrypto
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

