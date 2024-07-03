#!/usr/bin/env bash

set -e

export LIBXML_DIR=$(pwd)
export MAKEFLAGS=-j$(nproc)
export NOCONFIGURE=1
./autogen.sh

git clone https://github.com/sparklemotion/nokogiri
cd nokogiri
bundle install
bundle exec rake compile -- --with-xml2-source-dir=${LIBXML_DIR}
bundle exec rake test
