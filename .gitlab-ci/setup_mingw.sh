#!/bin/sh

prefix=
if [ -n "$MINGW_PACKAGE_PREFIX" ]; then
    prefix="${MINGW_PACKAGE_PREFIX}-"
fi

pacman --noconfirm -Syu
pacman --noconfirm -S --needed \
    ${prefix}autotools \
    ${prefix}cmake \
    ${prefix}libiconv \
    ${prefix}ninja \
    ${prefix}python \
    ${prefix}xz \
    ${prefix}zlib
