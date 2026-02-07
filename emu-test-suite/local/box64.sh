#!/usr/bin/env bash

git clone https://github.com/ptitSeb/box64
cd box64 && mkdir build && cd build
cmake .. ${OPTIONS} && make -j$(nproc)
sudo cp box64 /usr/local/bin/
