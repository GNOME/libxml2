#!/usr/bin/env bash

export DEBIAN_FRONTEND=noninteractive
export FUZZING_LANGUAGE=c

git clone https://github.com/zhangutah/oss-fuzz-harnessagent -b filter_libxml2 /src/oss-fuzz

# Copy the libxml2 repository from GitLab CI workspace to /src/libxml2
mkdir -p /src
cp -r "$CI_PROJECT_DIR" /src/libxml2
cd /src/libxml2 || exit 1

apt-get update && \
apt-get install -y --no-install-recommends make autoconf libtool pkg-config zlib1g-dev liblzma-dev && \
curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb && \
apt install ./automake_1.16.5-1.3_all.deb && \
mv /src/oss-fuzz/projects/libxml2/all_harnesses/ /src/all_harnesses && \
cp /src/oss-fuzz/projects/libxml2/build.sh /src/build.sh && \
compile || exit 1

# Extract binary names from build.sh and run them
BINARIES=$(grep -oP '(?<=-o \$OUT/)[^\s\\]+' /src/build.sh)

for binary in $BINARIES; do
  if [ -f "/out/$binary" ]; then
    echo "Running $binary..."
    savedcorpdir=/tmp/saved_corp_${binary}
    mkdir -p $savedcorpdir
    /out/$binary -runs=10000 $savedcorpdir /tmp/corpus >/dev/null 2>&1
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -ne 0 ]; then
      echo "Binary $binary crashed with exit code $EXIT_CODE"
      
      # Find crash file in current directory
      CRASH_FILE=$(find . -maxdepth 1 -name "crash-*" -type f | head -n 1)
      
      if [ -n "$CRASH_FILE" ]; then
        echo "Crash sample: $CRASH_FILE"
        echo "Base64 encoded crash sample:"
        base64 "$CRASH_FILE"
      fi
      
      exit $EXIT_CODE
    fi
  else
    echo "Binary $binary not found, skipping..."
  fi
done