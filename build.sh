#!/bin/bash

mkdir build
cd build
cmake ..
make
sudo python ../testing/test_logger.py
