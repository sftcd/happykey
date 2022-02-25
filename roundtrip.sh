#!/bin/bash

# set -x

# Copyright 2019-2022 Stephen Farrell. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# An OpenSSL-based HPKE implementation of RFC9180
#
# If you wanna use valgrind uncomment this
# VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"

# make a tmpdir, generate a key pair, encrypt and try decrypt

# just in case...
BINDIR=$HOME/code/happykey
# LD_LIBRARY_PATH...
. $BINDIR/env

if [ ! -f $BINDIR/hpkemain ]
then
    echo "You probably need to run make first ..."
    exit 1
fi


SCRATCH=$BINDIR/scratch
mkdir -p $SCRATCH

DICTFILE="/usr/share/dict/words"

if [ ! -f $SCRATCH/plain ]
then
    # echo "Fetching new plaintext from https://jell.ie/news/ ..."
    # curl https://jell.ie/news/ >$SCRATCH/plain
    # use the first 1024 bytes of the dictionary
    if [ ! -f $DICTFILE ]
    then
        echo "Can't read $DICTFILE make some other plaintext - exiting"
        exit 88
    fi
    head -10 $DICTFILE >$SCRATCH/plain
fi

TMPNAM=`mktemp $SCRATCH/tmpXXXX`
cp $SCRATCH/plain $TMPNAM.plain

echo "Running: $VALGRIND $BINDIR/hpkemain -k -p $TMPNAM.priv -P $TMPNAM.pub $*"
$VALGRIND $BINDIR/hpkemain -k -p $TMPNAM.priv -P $TMPNAM.pub $*
echo "Running $VALGRIND $BINDIR/hpkemain -e -P $TMPNAM.pub -i $TMPNAM.plain -o $TMPNAM.cipher  $*"
$VALGRIND $BINDIR/hpkemain -e -P $TMPNAM.pub -i $TMPNAM.plain -o $TMPNAM.cipher  $*
res=$?
if [[ "$res" != "0" ]]
then
    echo "Oops - encrypting failed! - exiting"
    exit 1
fi

# Next line is handy when debugging with gdb
echo "Running: $BINDIR/hpkemain -d -p $TMPNAM.priv -i $TMPNAM.cipher $*"
$VALGRIND $BINDIR/hpkemain -d -p $TMPNAM.priv -i $TMPNAM.cipher -o $TMPNAM.recovered $*
res=$?
if [[ "$res" == "0" ]]
then
    echo "All seems well!"
fi


