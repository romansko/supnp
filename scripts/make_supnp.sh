#!/bin/sh
# run from supnp root
./bootstrap && ./configure --enable-supnp && make && cd simulation && make
