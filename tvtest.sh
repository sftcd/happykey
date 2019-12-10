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

for mode in base psk auth pskauth
do
	for kem in 1 2 3 4
	do
	    for kdf in 1 2 
	    do
	        for aead in 1 2 3 
	        do
	            $BINDIR/hpkemain -T -m $mode -c $kem,$kdf,$aead >/dev/null 
	            res=$?
	            if [[ "$res" == "0" ]]
	            then
	                echo "$mode,$kem,$kdf,$aead is good"
	            else
	                echo "$mode,$kem,$kdf,$aead is BAD!"
	            fi
	        done
	    done
	done
done
