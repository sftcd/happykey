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

# make a tmpdir, generate a key pair, encrypt and try decrypt, with
# various combinations of good/bad info and aad inputs

# If you wanna use valgrind uncomment this
VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"

# just in case...
BINDIR=$HOME/code/happykey
# LD_LIBRARY_PATH...
. $BINDIR/env

if [ ! -f $BINDIR/hpkemain ]
then
    echo "You probably need to run make first ..."
    exit 1
fi

# we'll use random values for good/bad aad and info
GOODPSK="$RANDOM$RANDOM"
BADPSK="$RANDOM$RANDOM"
GOODPSKID="$RANDOM$RANDOM"
BADPSKID="$RANDOM$RANDOM"

SCRATCH=$BINDIR/scratch
mkdir -p $SCRATCH

if [ ! -f $SCRATCH/plain ]
then
    echo "$RANDOM$RANDOM$RANDOM$RANDOM" >>$SCRATCH/plain
    echo "$RANDOM$RANDOM$RANDOM$RANDOM" >>$SCRATCH/plain
    echo "$RANDOM$RANDOM$RANDOM$RANDOM" >>$SCRATCH/plain
fi

TMPNAM=`mktemp $SCRATCH/tmpXXXX`
cp $SCRATCH/plain $TMPNAM.plain

# new recipient key pair
$VALGRIND $BINDIR/hpkemain -k -p $TMPNAM.rpriv -P $TMPNAM.rpub
# new sender key pair for auth modes
$VALGRIND $BINDIR/hpkemain -k -p $TMPNAM.spriv -P $TMPNAM.spub

for mode in base psk auth pskauth
do

    # encrypt
    $VALGRIND $BINDIR/hpkemain -e -P $TMPNAM.rpub -p $TMPNAM.spriv \
        -i $TMPNAM.plain -o $TMPNAM.cipher -m $mode -s $GOODPSK -n $GOODPSKID

    # check decryption fails as expected
    echo "Good mode: $mode psk: $GOODPSK pskid $GOODPSKID"
    for psk in $GOODPSK $BADPSK
    do
        for pskid in $GOODPSKID $BADPSKID
        do
            if [[ "$VALGRIND" == "" ]]
            then
                 $BINDIR/hpkemain -d -p $TMPNAM.spriv -P $TMPNAM.rpub \
                     -i $TMPNAM.cipher -o $TMPNAM.recovered -m $mode -s $psk -n $pskid 2>/dev/null
            else
                $VALGRIND $BINDIR/hpkemain -d -p $TMPNAM.spriv -p $TMPNAM.rpub \
                    -i $TMPNAM.cipher -o $TMPNAM.recovered -m $mode -s $psk -n $pskid 
            fi
            res=$?
            if [[ "$res" == "0" ]]
            then
                strres="good"
            else
                strres="error"
            fi
            echo "$mode $psk $pskid results in $res/$strres"
        done
    done
done


