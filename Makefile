# Copyright 2019-2022 Stephen Farrell. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# An OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
#

# Typical (for me) place where an OpenSSL build may reside
# (you can over-ride this from command line)
OSSL?=../openssl

# OpenSSL includes
INCL=${OSSL}/include

# basic settings
CC=gcc
CFLAGS=-D HAPPYKEY -g

# build a command line tool and a test tool that use
# the polyfill version of the API implementation
all: hpkemain apitest

# main build targets
hpke.o: hpke.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

hpke_oldapi.o: hpke_oldapi.c hpke_oldapi.h hpke_util.h hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

hpke_util.o: hpke_util.c hpke_util.h hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

hpkemain.o: hpkemain.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

apitest.o: apitest.c hpke.h hpke.c
	${CC} ${CFLAGS} -I ${INCL} -c $<

packet.o: packet.c
	${CC} ${CFLAGS} -g -I ${INCL} -c $<

apitest: apitest.o hpke.o hpke_oldapi.o hpke_util.o packet.o
	${CC} ${CFLAGS} -o $@ apitest.o hpke.o hpke_oldapi.o hpke_util.o packet.o -lssl -lcrypto

hpkemain: hpkemain.o hpke.o hpke_oldapi.o hpke_util.o packet.o
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o hpke_oldapi.o hpke_util.o packet.o -lssl -lcrypto

# this is the example from the HPKE documentation, it requires
# an OpenSSL build that includes HPKE
pod_example.o: pod_example.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

pod_example: pod_example.o
	${CC} ${CFLAGS} -o $@ pod_example.o -L${OSSL} -lssl -lcrypto

pod_example_test: pod_example
	LD_LIBRARY_PATH=${OSSL} ./pod_example

clean:
	- rm -f hpkemain.o hpke.o hpke_util.o hpketv.o hpkemain
	- rm -f apitest apitest.o packet.o
	- rm -f pod_example pod_example.o
