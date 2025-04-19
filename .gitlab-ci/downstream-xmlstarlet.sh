#!/bin/sh

set -e

srcdir=$(pwd)
installdir="$srcdir/install"
# xmlstarlet uses xml2-config
export PATH="$installdir/bin:$PATH"

# We can't use --depth 1 because configure calls git-describe
# which needs the branch history.
git clone --single-branch https://github.com/nwellnhof/xmlstar.git
cd xmlstar
autoreconf -sif
./configure
make
LD_LIBRARY_PATH="$installdir/lib" make check
