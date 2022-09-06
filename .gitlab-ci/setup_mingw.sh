#!/bin/sh

pacman --noconfirm -Syu

prefix=
if [ -n "$MINGW_PACKAGE_PREFIX" ]; then
    prefix="${MINGW_PACKAGE_PREFIX}-"
fi
for module in libiconv python xz zlib "$@"; do
    pacman --noconfirm -S --needed ${prefix}$module
done
