#!/bin/bash -eu

# OSS-Fuzz integration, see
# https://github.com/google/oss-fuzz/tree/master/projects/libxml2

# Add extra UBSan checks
if [ "$SANITIZER" = undefined ]; then
    extra_checks="integer,float-divide-by-zero"
    extra_cflags="-fsanitize=$extra_checks -fno-sanitize-recover=$extra_checks"
    export CFLAGS="$CFLAGS $extra_cflags"
    export CXXFLAGS="$CXXFLAGS $extra_cflags"
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
