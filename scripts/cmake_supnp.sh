#!/bin/sh
# run from supnp root (./scripts/cmake_supnp.sh)
cmake -DENABLE_SUPNP=ON . && make && cd simulation && make
