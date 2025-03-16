#!/bin/sh

set -e

srcdir=$(pwd)

mkdir -p install
installdir="$srcdir/install"
export PKG_CONFIG_PATH="$installdir/lib/pkgconfig"

sh autogen.sh "--prefix=$installdir" --without-python
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

git clone --depth 1 https://github.com/php/php-src.git
cd php-src
./buildconf
./configure --with-xsl --enable-soap --enable-debug
make -j$(nproc)
make TESTS=" \
    -g FAIL \
    --no-progress \
    ext/dom \
    ext/libxml \
    ext/simplexml \
    ext/soap \
    ext/xml \
    ext/xmlreader \
    ext/xmlwriter \
    ext/xsl \
" test
