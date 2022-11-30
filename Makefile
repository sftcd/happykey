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

CC=gcc
CFLAGS=-D HAPPYKEY -g

all: hpkemain apitest

# This is how I used remove the polyfill code and copy over to the
# OpenSSL build. We'll be doing the reverse here so will remove this
# but handy to keep some for the moment.
#
# hpke.c, hpke.h and apitest.c include additional tracing and test vector
# support that's not desirable in the version we'd like to see merged
# with OpenSSL - we use the unifdef tool to generate files for using in
# an openssl build from the ones here.
#
# The "-x 1" below is just to get unifdef to return zero if the input
# and output differ, which should be the case for us.
# forlib: hpke.c-forlib hpke_util.c-forlib hpke.h-forlib hpke_util.h-forlib apitest.c-forlib
#
# hpke.c-forlib: hpke.c
# 	- unifdef -x 1 -DHPKEAPI -UHAPPYKEY -USUPERVERBOSE -UTESTVECTORS hpke.c >hpke.c-forlib
# copy over the files to the openssl build
#copy2lib: forlib \
#		  ${OSSL}/crypto/hpke/hpke.c \
#		  ${OSSL}/crypto/hpke/hpke_util.c \
#		  ${INCL}/openssl/hpke.h \
#		  ${INCL}/internal/hpke_util.h \
#		  ${OSSL}/test/hpke_test.c
#
#${OSSL}/crypto/hpke/hpke.c: hpke.c-forlib
#	- cp hpke.c-forlib ${OSSL}/crypto/hpke/hpke.c

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

apitest: apitest.o hpke.o hpke_util.o packet.o
	${CC} ${CFLAGS} -o $@ apitest.o hpke.o hpke_util.o packet.o -lssl -lcrypto

hpkemain: hpkemain.o hpke.o hpke_util.o packet.o
	${CC} ${CFLAGS} -o $@ hpkemain.o hpke.o hpke_util.o packet.o -lssl -lcrypto

pod_example.o: pod_example.c hpke.h
	${CC} ${CFLAGS} -I ${INCL} -c $<

pod_example: pod_example.o
	${CC} ${CFLAGS} -o $@ pod_example.o hpke.o hpke_util.o packet.o -lssl -lcrypto

clean:
	- rm -f hpkemain.o hpke.o hpke_util.o hpketv.o hpkemain
	- rm -f apitest apitest.o packet.o
	- rm -f pod_example pod_example.o
