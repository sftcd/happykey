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

CC=gcc
CFLAGS=-D HAPPYKEY -g

# There are test vectors for this - see comments in hpketv.h.
# If you want to compile in test vector checks then uncomment
# the next line:
# CFLAGS=-D HAPPYKEY -g -D TESTVECTORS -I ../json-c

all: hpkemain apitest

# hpke.c, hpke.h and apitest.c include additional tracing and test vector
# support that's not desirable in the version we'd like to see merged
# with OpenSSL - we use the unifdef tool to generate files for using in
# an openssl build from the ones here. 

#
# The "-x 1" below is just to get unifdef to return zero if the input
# and output differ, which should be the case for us.
forlib: hpke.c-forlib hpke_util.c-forlib hpke.h-forlib hpke_util.h-forlib apitest.c-forlib

hpke.c-forlib: hpke.c
	- unifdef -x 1 -DHPKEAPI -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke.c >hpke.c-forlib

hpke_util.c-forlib: hpke_util.c
	- unifdef -x 1 -DHPKEAPI -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke_util.c >hpke_util.c-forlib

hpke.h-forlib: hpke.h
	- unifdef -x 1 -DHPKEAPI -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke.h >hpke.h-forlib

hpke_util.h-forlib: hpke_util.h
	- unifdef -x 1 -DHPKEAPI -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke_util.h >hpke_util.h-forlib

apitest.c-forlib: apitest.c
	- unifdef -x 1 -DHPKEAPI -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS apitest.c >apitest.c-forlib

forlibclean:
	- rm -f hpke.h-forlib
	- rm -f hpke_util.h-forlib
	- rm -f hpke_util.c-forlib
	- rm -f hpke.c-forlib
	- rm -f apitest.c-forlib

# copy over the files to the openssl build
copy2lib: forlib
	- cp hpke.c-forlib ${OSSL}/crypto/hpke/hpke.c
	- cp hpke_util.c-forlib ${OSSL}/crypto/hpke/hpke_util.c
	- cp hpke.h-forlib ${INCL}/openssl/hpke.h
	- cp hpke_util.h-forlib ${INCL}/internal/hpke_util.h
	- cp apitest.c-forlib ${OSSL}/test/hpke_test.c

# main build targets
hpke.o: hpke.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

hpke_util.o: hpke_util.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

hpkemain.o: hpkemain.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

apitest.o: apitest.c hpke.h hpke.c
	${CC} ${CFLAGS} -I ${INCL} -c $<

packet.o: packet.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

hpketv.o: hpketv.c hpketv.h hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

apitest: apitest.o hpke.o hpke_util.o packet.o
	${CC} ${CFLAGS} -o $@ apitest.o hpke.o hpke_util.o packet.o -lssl -lcrypto

apitest-forlib: apitest.o hpke-forlib.o hpke_util.o packet.o
	${CC} ${CFLAGS} -o $@ apitest.o hpke-forlib.o hpke_util.o packet.o -L ${OSSL} -lssl -lcrypto

hpkemain: hpkemain.o hpke.o hpke_util.o packet.o
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o hpke_util.o packet.o -lssl -lcrypto

pod_example.o: pod_example.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

pod_example: pod_example.o
	${CC} ${CFLAGS} -o $@ pod_example.o hpke.o hpke_util.o packet.o -lssl -lcrypto

doc: hpke.c hpke.h hpketv.h hpketv.c apitest.c
	doxygen hpke.doxy
	(cd doxy/latex; make; mv refman.pdf ../../hpke-api.pdf )

docclean:
	- rm -rf doxy

clean: forlibclean docclean oddityclean
	- rm -f hpkemain.o hpke.o hpke_util.o hpketv.o hpkemain 
	- rm -f apitest apitest.o packet.o
	- rm -f pod_example pod_example.o

# stuff below here are various odd tests done now and then
# can probably be deleted now

oddityclean:
	- rm -f neod neod.o neod_nss.o 
	- rm -f oeod oeod.o
	- rm -f osslplayground osslplayground.o
	- rm -f test2evp test2evp.o
	- rm -rf scratch/*
	- rm -f kgikm kgikm.o
	- rm -f os2evp os2evp.o
	- rm -f deleak

oddity: neod oeod test2evp osslplayground kgikm os2evp

deleak.o: deleak.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

deleak: deleak.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ deleak.o -L ${OSSL} -lssl -lcrypto

os2evp: os2evp.o hpke.o hpke_util.o packet.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ os2evp.o hpke.o hpke_util.o packet.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4

os2evp.o: os2evp.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

kgikm: kgikm.o hpke.o hpke_util.o packet.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ kgikm.o hpke.o hpke_util.o packet.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4

kgikm.o: kgikm.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

osslplayground: osslplayground.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ osslplayground.o hpke.o hpke_util.o packet.o -L ${OSSL} -lcrypto -L ${NSSL} -lnss3 -lnspr4


osslplayground.o: osslplayground.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

# This is a round-trip test with NSS encrypting and my code decrypting
# (no parameters for now)

neod: neod.o hpke.o hpke_util.o neod_nss.o packet.o
	if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${OSSL}:${NSSL} ${CC} ${CFLAGS}  -g -o $@ neod.o hpke.o hpke_util.o packet.o neod_nss.o -L ${OSSL} -lssl -lcrypto -L ${NSSL} -lnss3 -lnspr4 ; fi

neod.o: neod.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

neod_nss.o: neod_nss.c
	if [ -d ${NSSL} ]; then ${CC} -g ${CFLAGS} ${NINCL} -c $< ; fi

neodtest: neod
	- if [ -d ${NSSL} ]; then LD_LIBRARY_PATH=${OSSL}:${NSSL} ./neod ; fi

# A round-trip to test EVP mode for sender public
#
oeod: oeod.o hpke.o hpke_util.o packet.o 
	${CC} ${CFLAGS} -g -o $@ oeod.o hpke.o hpke_util.o packet.o -L ${OSSL} -lssl -lcrypto 

oeod.o: oeod.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

# A test of a buffer->EVP_PKEY problem
test2evp: test2evp.o hpke.o hpke_util.o packet.o
	LD_LIBRARY_PATH=${OSSL} ${CC} ${CFLAGS} -g -o $@ test2evp.o hpke.o hpke_util.o packet.o -L ${OSSL} -lssl -lcrypto 

test2evp.o: test2evp.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<
