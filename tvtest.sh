#!/bin/bash

# set -x

# Copyright 2019, 2020 Stephen Farrell. All Rights Reserved.
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


function usage()
{
    echo "$0 [-hvV] - test HPKE test vectors"
    echo "  -t <file> to use the given test vector file"
    echo "  -h means print this"
    echo "  -v means be verbose"
    echo "  -s means be super-verbose"
    echo "  -V means run with valgrind"
    exit 99
}
# default values for parameters
verbose="no"
superverbose="no"
VG="no"

# We're used to guess which draft, based on the content of 
# the Makefile. (Yes, that's iccky, but shouldn't be needed
# for long I hope;-)
# mline=`grep DRAFT_07 Makefile | grep CFLAGS`
# TVFILE="test-vectors-06.json"
# if [[ "${mline:0:1}" == "C" ]]
# then
    # TVFILE="test-vectors-07.json"
# fi

TVFILE="test-vectors-07.json"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(/usr/bin/getopt -s bash -o hst:vV -l help,super,testvectors:,verbose,valgrind -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -h|--help) usage;;
        -s|--super) superverbose="yes" ;;
        -t|--testvectors) TVFILE=$2; shift ;;
        -v|--verbose) verbose="yes" ;;
        -V|--valgrind) VG="yes" ;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done


goodcnt=0
badcnt=0
notvcnt=0

for mode in base psk auth pskauth
do
	for kem in 0x10 0x11 0x12 0x20 0x21
	do
	    for kdf in 1 2 3
	    do
	        for aead in 1 2 3 
	        do

                if [[ "$VG" == "yes" ]]
                then
                    VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
	                $VALGRIND $BINDIR/hpkemain -T$TVFILE -m $mode -c $kem,$kdf,$aead 
                else 
                    if [[ "$superverbose" == "yes" ]]
                    then
                        echo "====="
                        echo "Running: $BINDIR/hpkemain -T$TVFILE -m $mode -c $kem,$kdf,$aead"
	                    $BINDIR/hpkemain -T$TVFILE -m $mode -c $kem,$kdf,$aead 
                    else
	                    $BINDIR/hpkemain -T$TVFILE -m $mode -c $kem,$kdf,$aead >/dev/null 2>&1
                    fi
                fi
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
