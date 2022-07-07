#!/bin/bash

# Replace the HPKE code fragment for test/evp_extra_test.c 
# with out latest fragment. Messy, but temporary.

# set -x

tmpf=`mktemp dosubXXXX`

cat $1 | \
    sed -e '
        /HPKETESTSTART/,/HPKETESTEND/!b
        //!d;/HPKETESTEND/!b
        r apitest.c-frag-forlib
        N
      ' >$tmpf

if [ ! -x $tmpf ]
then
    mv $tmpf $1
    exit 0
else
    rm -f $tmpf
    exit 1
fi
