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

# make a tmpdir, generate a key pair, encrypt and try decrypt

# just in case...
BINDIR=$HOME/code/happykey
# LD_LIBRARY_PATH...
. $BINDIR/env

SCRATCH=$BINDIR/scratch
mkdir -p $SCRATCH

if [ ! -f $SCRATCH/plain ]
then
    echo "Fetching new plaintext..."
    curl https://jell.ie/news/ >$SCRATCH/plain
fi

TMPNAM=`mktemp $SCRATCH/tmpXXXX`
cp $SCRATCH/plain $TMPNAM.plain

$BINDIR/hpkemain -k -p $TMPNAM.priv -P $TMPNAM.pub
$BINDIR/hpkemain -e -P $TMPNAM.pub -i $TMPNAM.plain -o $TMPNAM.cipher

# Next line is handy when debugging with gdb
# echo "RUnning: $BINDIR/hpkemain -d -p $TMPNAM.priv -i $TMPNAM.cipher"
$BINDIR/hpkemain -d -p $TMPNAM.priv -i $TMPNAM.cipher -o $TMPNAM.recovered
res=$?
if [[ "$res" == "0" ]]
then
    echo "All seems well!"
fi


