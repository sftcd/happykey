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

# run through all the options and see what happens

# If you wanna use valgrind uncomment this
# VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"

# if you want verbose output...
# VERBOSE=yes

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

if [ ! -f $SCRATCH/plain ]
then
    echo "$RANDOM$RANDOM$RANDOM$RANDOM" >>$SCRATCH/plain
    echo "$RANDOM$RANDOM$RANDOM$RANDOM" >>$SCRATCH/plain
    echo "$RANDOM$RANDOM$RANDOM$RANDOM" >>$SCRATCH/plain
fi

TMPNAM=`mktemp $SCRATCH/tmpXXXX`
cp $SCRATCH/plain $TMPNAM.plain

# overall result
overall=0

# count things
passed=0
failed=0

# go through the modes, kems... (kdfs,aeads later)
for mode in base psk auth pskauth
do
	for kem in 0x10 0x11 0x12 0x20 0x21
	do
        # new recipient key pair - only the KEM matters for key generation
        $VALGRIND $BINDIR/hpkemain -k -p $TMPNAM.$mode.$kem.rpriv -P $TMPNAM.$mode.$kem.rpub -m $mode -c $kem,1,1
        res=$?
        if [[ "$res" != 0 ]]
        then
            echo "$mode,$kem recipient key gen failed!"
            overall=1
            failed=$((failed+1))
            continue
        else
            passed=$((passed+1))
        fi


        # if a psk mode then generate both good and bad PSK and PSKID
        if [[ "$mode" == "psk" || "$mode" == "pskauth" ]]
        then
            GOODPSKPARMS="-s $RADNDOM$RANDOM -n $RANDOM$RANDOM"
            BADPSKPARMS="-s $RADNDOM$RANDOM -n $RANDOM$RANDOM"
        else
            GOODPSKPARMS=" "
            BADPSKPARMS=" "
        fi

        if [[ "$mode" == "auth" || "$mode" == "pskauth" ]]
        then
            # new sender key pair for auth modes
            $VALGRIND $BINDIR/hpkemain -k -p $TMPNAM.$mode.$kem.spriv -P $TMPNAM.$mode.$kem.spub -m $mode -c $kem,1,1
            if [[ "$res" != 0 ]]
            then
                echo "$mode,$kem sender key gen failed!"
                overall=1
                failed=$((failed+1))
                continue
            else
                passed=$((passed+1))
            fi
            AUTHEPARMS="-p $TMPNAM.$mode.$kem.spriv "
            AUTHDPARMS="-P $TMPNAM.$mode.$kem.spub "
        else
            AUTHEPARMS=" "
            AUTHDPARMS=" "
        fi

        # go through the kdfs aeads...
	    for kdf in 1 2 3 
	    do
	        for aead in 1 2 3 
	        do

                # setup good info/aad

                # setup overall result optimistically
                ores=0

                # encrypt
                $VALGRIND $BINDIR/hpkemain -e -P $TMPNAM.$mode.$kem.rpub $AUTHEPARMS $GOODPSKPARMS \
                    -i $TMPNAM.plain -o $TMPNAM.$mode.$kem.$kdf.$aead.cipher \
                    -m $mode -c $kem,$kdf,$aead
	            res=$?
                if [[ "$res" != 0 ]]
                then
                    # encrypt failed!
	                echo "$mode,$kem,$kdf,$aead ENCRYPT FAILED!"
                    echo "What failed was: "
                    echo "$BINDIR/hpkemain -e -P $TMPNAM.$mode.$kem.rpub $AUTHEPARMS $GOODPSKPARMS \
                    -i $TMPNAM.plain -o $TMPNAM.$mode.$kem.$kdf.$aead.cipher \
                    -m $mode -c $kem,$kdf,$aead"
                    ores=1
                    overall=1
                    failed=$((failed+1))
                else
                    # this refers to the encrypt above
                    passed=$((passed+1))
                    # should be good decrypt
                    $VALGRIND $BINDIR/hpkemain -d -p $TMPNAM.$mode.$kem.rpriv $AUTHDPARMS $GOODPSKPARMS \
                        -i $TMPNAM.$mode.$kem.$kdf.$aead.cipher -o $TMPNAM.$mode.$kem.$kdf.$aead.recovered \
                        -m $mode -c $kem,$kdf,$aead 
	                res=$?
                    if [[ "$res" != "0" || ! -f $TMPNAM.$mode.$kem.$kdf.$aead.recovered ]]
                    then
                        # decrypt failed!
                        echo "$mode,$kem,$kdf,$aead DECRYPT FAILED when it shouldn't!"
                        echo "What failed was: "
                        echo "$BINDIR/hpkemain -d -p $TMPNAM.$mode.$kem.rpriv $AUTHDPARMS $GOODPSKPARMS \
                        -i $TMPNAM.$mode.$kem.$kdf.$aead.cipher -o $TMPNAM.$mode.$kem.$kdf.$aead.recovered \
                        -m $mode -c $kem,$kdf,$aead"
                        overall=1
                        ores=1
                        failed=$((failed+1))
                    else
                        passed=$((passed+1))
                        # try some bad decrypts - these should fail
                        ores=0

                        # give bad PSK stuff
                        if [[ "$mode" == "psk" || "$mode" == "pskauth" ]]
                        then
                            $VALGRIND $BINDIR/hpkemain -d -p $TMPNAM.$mode.$kem.rpriv $AUTHDPARMS $BADPSKPARMS \
                                -i $TMPNAM.$mode.$kem.$kdf.$aead.cipher -o $TMPNAM.$mode.$kem.$kdf.$aead.unrecovered \
                                -m $mode -c $kem,$kdf,$aead  2>/dev/null
                            res=$?
                            if [[ "$res" == 0 || -f $TMPNAM.$mode.$kem.$kdf.$aead.unrecovered ]]
                            then
                                echo "$mode,$kem,$kdf,$aead DECRYPT WORKED when it shouldn't!"
                                overall=1
                                ores=1
                                failed=$((failed+1))
                            else
                                # echo "$mode,$kem,$kdf,$aead DECRYPT failed as planned"
                                passed=$((passed+1))
                            fi
                        fi

                        # give bad info/aad

                    fi
                fi

	            if [[ "$ores" == "0" ]]
	            then
                    if [[ "$VERBOSE" != "" ]]
                    then
	                    echo "$mode,$kem,$kdf,$aead is good"
                    fi
	            else
	                echo "$mode,$kem,$kdf,$aead is BAD!"
	            fi

	        done
	    done
	done
done
if [[ "$overall" == "0" ]]
then
    echo "All done. All good. ($passed tests)"
else
    echo "Some problems - passed: $passed but failed: $failed "
fi
