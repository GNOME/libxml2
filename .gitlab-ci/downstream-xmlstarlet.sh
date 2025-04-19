#!/bin/sh

set -e

srcdir=$(pwd)
installdir="$srcdir/install"
# xmlstarlet uses xml2-config
export PATH="$installdir/bin:$PATH"

git clone --depth 1 https://github.com/nwellnhof/xmlstar.git
cd xmlstar
autoreconf -sif
./configure
make
LD_LIBRARY_PATH="$installdir/lib" make check
