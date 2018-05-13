#!/bin/bash

make clean && make
./ci/configd_base_test.sh
