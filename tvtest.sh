#!/bin/bash

# set -x

# Copyright 2019 Stephen Farrell. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# An OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
#
# I plan to use this for my ESNI-enabled OpenSSL build (https://github.com/sftcd/openssl)
# when the time is right.

# run through all the ciphesuite and mode options and see
# what happens

# just in case...
BINDIR=$HOME/code/happykey
# LD_LIBRARY_PATH...
. $BINDIR/env

if [ ! -f $BINDIR/hpkemain ]
then
    echo "You probably need to run make first ..."
    exit 1
fi

# check hpkemain is built with testvectors
$BINDIR/hpkemain -T -h >/dev/null 2>&1
res=$?
if [[ "$res" != "0" ]]
then
    echo "You need to build hpkemain with testvectors - see README.md"
    exit 2
fi

goodcnt=0
badcnt=0
notvcnt=0
verbose="no"

for mode in base psk auth pskauth
do
	for kem in 0x10 0x11 0x12 0x20 0x21
	do
	    for kdf in 1 2 3
	    do
	        for aead in 1 2 3 
	        do
	            $BINDIR/hpkemain -T -m $mode -c $kem,$kdf,$aead >/dev/null 2>&1 
	            res=$?
	            if [[ "$res" == "0" ]]
	            then
                    if [[ "$verbose" == "yes" ]]
                    then
	                    echo "$mode,$kem,$kdf,$aead is good"
                    fi
                    goodcnt=$((goodcnt+1))
                elif [[ "$res" == "2" ]]
                then
                    if [[ "$verbose" == "yes" ]]
                    then
	                    echo "No test vector for: $mode,$kem,$kdf,$aead"
                    fi
                    notvcnt=$((notvcnt+1))
	            else
                    if [[ "$verbose" == "yes" ]]
                    then
	                    echo "$mode,$kem,$kdf,$aead is BAD!"
                    fi
                    badcnt=$((badcnt+1))
	            fi
	        done
	    done
	done
done

echo "Good: $goodcnt, Bad: $badcnt, No test vector: $notvcnt"
