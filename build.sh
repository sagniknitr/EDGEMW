#!/bin/bash

cmake .
make
sudo python ./testing/test_logger.py
