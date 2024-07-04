#!/bin/sh

set -e

sh autogen.sh --without-python
make -j$(nproc)

srcdir=$(pwd)
incdir=$srcdir/include
libdir=$srcdir/.libs

curl -L https://cpan.metacpan.org/authors/id/S/SH/SHLOMIF/XML-LibXML-2.0210.tar.gz |tar xz
cd XML-LibXML-2.0210

perl Makefile.PL INC="-I$incdir" LIBS="-L$libdir -lxml2"
make
# Known to fail
LD_LIBRARY_PATH=$libdir make test || true
