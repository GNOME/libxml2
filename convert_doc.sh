#!/bin/sh

set -e

for file in *.c include/libxml/*.h; do
    sed -E -i '' -f convert_doc.sed $file
done

for file in include/libxml/*.h; do
    if [ $file != 'include/libxml/xmlversion.h' ]; then
        sed -E -i '' -e '1 s,/\*,/**\n * @file\n * ,' $file
    fi
done
