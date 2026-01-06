#!/usr/bin/env bash

cd /src

git clone https://github.com/zhangutah/oss-fuzz-harnessagent 

git clone --depth=1 https://github.com/gnome/libxml2 && \
  cd libxml2 && \
  apt-get install -y --no-install-recommends     make autoconf libtool pkg-config     zlib1g-dev liblzma-dev && \
  curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb &&     apt install ./automake_1.16.5-1.3_all.deb && \
  mv /src/oss-fuzz/projects/libxml2/all_harnesses/ /src/all_harnesses && \
  cp /src/oss-fuzz/projects/libxml2/build.sh /src/build.sh

compile

/out/xmlparseurisafe -max_total_time=10