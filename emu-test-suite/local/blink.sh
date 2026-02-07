#!/usr/bin/env bash

git clone https://github.com/jart/blink.git
cd blink
./configure && make -j$(nproc) && sudo make install
