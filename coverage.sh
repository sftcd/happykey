#!/bin/bash

# Use lcov to generate test coverage figures for an OpenSSL build
# run this from the top of the OpenSSL source 

# set -x

# if starting from scratch this needs:
#   ./config --debug --coverage no-asm no-afalgeng no-shared -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
make -j8 
make test TESTS=test_hpke
lcov -d . -c -o ./lcov.info
genhtml ./lcov.info --output-directory /tmp/mycov
