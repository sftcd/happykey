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
# VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"

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
GOODAAD="$RANDOM$RANDOM"
BADAAD="$RANDOM$RANDOM"
GOODINFO="$RANDOM$RANDOM"
BADINFO="$RANDOM$RANDOM"

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

# new key pair
$VALGRIND $BINDIR/hpkemain -k -p $TMPNAM.priv -P $TMPNAM.pub $*

# check decryption fails as expected
echo "Good aad: $GOODAAD info $GOODINFO"
for mode in base psk 
do

    # if a psk mode then generate both a PSK and PSKID
    if [[ "$mode" == "psk" || "$mode" == "pskauth" ]]
    then
        PSKPARMS="-s $RADNDOM$RANDOM -n $RANDOM$RANDOM"
    else
        PSKPARMS=" "
    fi

    # encrypt
    $VALGRIND $BINDIR/hpkemain -e -m $mode -P $TMPNAM.pub -i $TMPNAM.plain -o $TMPNAM.cipher -I $GOODINFO -a $GOODAAD $PSKPARMS $*
    res=$?
    if [[ "$res" != "0" ]]
    then
        echo "Exiting - failure to encrypt"
    fi
	for aad in $GOODAAD $BADAAD
	do
	    for info in $GOODINFO $BADINFO
	    do
	        if [[ "$VALGRIND" == "" ]]
	        then
	            $BINDIR/hpkemain -d -m $mode -p $TMPNAM.priv -i $TMPNAM.cipher -o $TMPNAM.recovered -I $info -a $aad $PSKPARMS $* 2>/dev/null
	        else
	            $VALGRIND $BINDIR/hpkemain -d -m $mode -p $TMPNAM.priv -i $TMPNAM.cipher -o $TMPNAM.recovered -I $info -a $aad $PSKPARMS  $*
	        fi
	        res=$?
	        if [[ "$res" == "0" ]]
	        then
	            strres="good"
	        else
	            strres="error"
	        fi
            if [[ "$aad" == "$GOODAAD" && "$info" == "$GOODINFO" ]]
            then
	            echo "Expected good: $mode $aad $info results in $res/$strres"
            else
	            echo "Expected error: $mode $aad $info results in $res/$strres"
            fi
	    done
	done
done
	
	
