#!/bin/bash

mkdir -p build/
cd build/
cmake ..
make -j12
cd ..

sudo python ./testing/test_socket.py
sudo python ./testing/test_logger.py
