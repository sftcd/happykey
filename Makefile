# Copyright 2019-2022 Stephen Farrell. All Rights Reserved.
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
SLONTIS_OSSL=../openssl-slontis
SLONTIS_INCL=${SLONTIS_OSSL}/include

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

# testvectors isn't compatible with apitest
ifdef testvectors
all: hpkemain neod oeod test2evp osslplayground kgikm os2evp
else
all: hpkemain apitest neod oeod test2evp osslplayground kgikm os2evp
endif

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
forlib: hpke.c-forlib hpke.h-forlib apitest.c-forlib

hpke.c-forlib: hpke.c
	- unifdef -x 1 -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke.c >hpke.c-forlib

hpke.h-forlib: hpke.h
	- unifdef -x 1 -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke.h >hpke.h-forlib

apitest.c-forlib: apitest.c
	- unifdef -x 1 -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS apitest.c >apitest.c-forlib

forlibclean:
	- rm -f hpke.h-forlib
	- rm -f hpke.c-forlib

copy2lib: forlib
	- cp hpke.c-forlib ${OSSL}/crypto/hpke/hpke.c
	- cp hpke.h-forlib ${INCL}/openssl/hpke.h
	- cp apitest.c-forlib ${OSSL}/test/hpke_test.c

os2evp: os2evp.o hpke.o packet.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ os2evp.o hpke.o packet.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4

os2evp.o: os2evp.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

kgikm: kgikm.o hpke.o packet.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ kgikm.o hpke.o packet.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4

kgikm.o: kgikm.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

osslplayground: osslplayground.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ osslplayground.o hpke.o packet.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4


osslplayground.o: osslplayground.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

# This is a round-trip test with NSS encrypting and my code decrypting
# (no parameters for now)

neod: neod.o hpke.o neod_nss.o packet.o
	if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${OSSL}:${NSSL} ${CC} ${CFLAGS}  -g -o $@ neod.o hpke.o packet.o neod_nss.o -L ${OSSL} -lssl -lcrypto -L ${NSSL} -lnss3 -lnspr4 ; fi

neod.o: neod.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

neod_nss.o: neod_nss.c
	if [ -d ${NSSL} ]; then ${CC} -g ${CFLAGS} ${NINCL} -c $< ; fi

neodtest: neod
	- if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${OSSL}:${NSSL} ./neod ; fi

# A round-trip to test EVP mode for sender public
#
oeod: oeod.o hpke.o packet.o 
	${CC} ${CFLAGS} -g -o $@ oeod.o hpke.o packet.o -L ${OSSL} -lssl -lcrypto 

oeod.o: oeod.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

# A test of a buffer->EVP_PKEY problem

test2evp: test2evp.o hpke.o packet.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ test2evp.o hpke.o packet.o -L ${OSSL} -lssl -lcrypto 

test2evp.o: test2evp.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

packet.o: packet.c
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

ifdef uselibcrypto
apitest: apitest.o packet.o ${OSSL}/libssl.so
	${CC} ${CFLAGS} -o $@ apitest.o -L ${OSSL} -lssl -lcrypto
else
apitest: apitest.o packet.o
	${CC} ${CFLAGS} -o $@ apitest.o hpke.o packet.o -L ${OSSL} -lssl -lcrypto
endif

ifdef testvectors
hpketv.o: hpketv.c hpketv.h hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<
endif

ifdef testvectors
hpkemain: hpkemain.o hpke.o hpketv.o packet.o
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o packet.o hpketv.o -L ${OSSL} -lssl -lcrypto -L ../json-c/ -ljson-c
else
ifdef uselibcrypto
hpkemain: hpkemain.o packet.o
	${CC} ${CFLAGS} -o $@ hpkemain.o packet.o -L ${OSSL} -lssl -lcrypto
else
hpkemain: hpkemain.o hpke.o packet.o
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o packet.o -L ${OSSL} -lssl -lcrypto
endif
endif

doc: hpke.c hpke.h hpketv.h hpketv.c apitest.c
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
	- rm -f apitest apitest.o
	- rm -f kgikm kgikm.o
	- rm -f os2evp os2evp.o

# round-trip test wht NSS of "alternative" HPKE OpenSSL code 

nss_slontis.o: nss_slontis.c
	${CC} ${CFLAGS} -g -I ${SLONTIS_INCL} -c $<

nss_slontis: nss_slontis.o neod_nss.o
	if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${OSSL}:${NSSL} ${CC} ${CFLAGS}  -g -o $@ nss_slontis.o neod_nss.o -L ${SLONTIS_OSSL} -lssl -lcrypto -L ${NSSL} -lnss3 -lnspr4 ; fi

nss_slontis-test:
	- if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${SLONTIS_OSSL}:${NSSL} ./nss_slontis ; fi
