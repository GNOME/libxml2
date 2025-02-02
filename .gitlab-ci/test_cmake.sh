#!/bin/sh

echo '### 1'
#set -e

which cmake
ls -l /mingw64/bin/cmake.exe
file /mingw64/bin/cmake.exe
/mingw64/bin/cmake.exe --version

echo CFLAGS="-Werror $CFLAGS" \
cmake "$@" \
    -DBUILD_SHARED_LIBS=$BUILD_SHARED_LIBS \
    -DCMAKE_INSTALL_PREFIX=libxml2-install \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -S . -B libxml2-build

CFLAGS="-Werror $CFLAGS" \
cmake "$@" \
    -DBUILD_SHARED_LIBS=$BUILD_SHARED_LIBS \
    -DCMAKE_INSTALL_PREFIX=libxml2-install \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -S . -B libxml2-build
echo '### 2'
cmake --build libxml2-build --target install
echo '### 3'

(cd libxml2-build && ctest -VV)

mkdir -p libxml2-install/share/libxml2
cp Copyright libxml2-install/share/libxml2
(cd libxml2-install &&
    tar -czf ../libxml2-$CI_COMMIT_SHORT_SHA-$SUFFIX.tar.gz *)
