#!/bin/bash -eu

# OSS-Fuzz integration, see
# https://github.com/google/oss-fuzz/tree/master/projects/libxml2

# Add all integer sanitizers
if [ "$SANITIZER" = undefined ]; then
    export CFLAGS="$CFLAGS -fsanitize=integer -fno-sanitize-recover=integer"
    export CXXFLAGS="$CXXFLAGS -fsanitize=integer -fno-sanitize-recover=integer"
fi

export V=1

./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-http \
    --without-python
make -j$(nproc)

cd fuzz
make clean-corpus
make fuzz.o

for fuzzer in api html regexp schema uri valid xinclude xml xpath; do
    make $fuzzer.o
    # Link with $CXX
    $CXX $CXXFLAGS \
        $fuzzer.o fuzz.o \
        -o $OUT/$fuzzer \
        $LIB_FUZZING_ENGINE \
        ../.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic

    if [ $fuzzer != api ]; then
        [ -e seed/$fuzzer ] || make seed/$fuzzer.stamp
        zip -j $OUT/${fuzzer}_seed_corpus.zip seed/$fuzzer/*
    fi
done

cp *.dict *.options $OUT/
