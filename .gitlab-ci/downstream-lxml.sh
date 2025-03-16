#!/bin/sh

set -e

srcdir=$(pwd)

mkdir -p install
installdir="$srcdir/install"
export PKG_CONFIG_PATH="$installdir/lib/pkgconfig"

sh autogen.sh "--prefix=$installdir" --with-http --with-zlib --without-python
make -j$(nproc)
make install

git clone --depth 1 https://gitlab.gnome.org/GNOME/libxslt.git
cd libxslt
sh autogen.sh \
    "--prefix=$installdir" \
    "--with-libxml-prefix=$installdir" \
    --without-python
make -j$(nproc)
make install
cd ..

git clone --depth 1 https://github.com/lxml/lxml.git
cd lxml
make
LD_LIBRARY_PATH="$installdir/lib" make TESTFLAGS='' test
