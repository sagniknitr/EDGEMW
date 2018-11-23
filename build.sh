#!/bin/bash

mkdir build
cd build
cmake ..
make
python testing/test_logger.py