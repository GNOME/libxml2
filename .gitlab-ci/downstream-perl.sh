#!/bin/sh

set -e

srcdir=$(pwd)
installdir="$srcdir/install"
incdir="$installdir/include/libxml2"
libdir="$installdir/lib"

git clone --depth 1 -b test-suite-libxml2 \
    https://github.com/nwellnhof/perl-XML-LibXML.git
cd perl-XML-LibXML

perl Makefile.PL INC="-I$incdir" LIBS="-L$libdir -lxml2"
make
make test
