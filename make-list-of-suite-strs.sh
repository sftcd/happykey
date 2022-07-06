#!/bin/bash

# Copyright 2019-2022 Stephen Farrell. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# An OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
#

# Make a list of the strings that we'll accept for HPKE suites.
# The output is included in an array in apitest.c

for kem in P-256 P-384 P-521 x25519 x448 0x10 0x11 0x12 0x20 0x21 16 17 18 32 33
do
    for kdf in hkdf-sha256 hkdf-sha384 hkdf-sha512 0x1 0x01 0x2 0x02 0x3 0x03 1 2 3
    do
        for aead in aes-128-gcm aes-256-gcm chacha20-poly1305 0x1 0x01 0x2 0x02 0x3 0x03 1 2 3
        do
            echo "\"$kem,$kdf,$aead\","
        done
    done 
done
