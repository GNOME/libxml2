#!/bin/sh

set -e

sh autogen.sh --without-python
make -j$(nproc)

srcdir=$(pwd)
incdir=$srcdir/include
libdir=$srcdir/.libs

git clone --depth 1 -b test-suite-libxml2 \
    https://github.com/nwellnhof/perl-XML-LibXML.git
cd perl-XML-LibXML

perl Makefile.PL INC="-I$incdir" LIBS="-L$libdir -lxml2"
make
make test
