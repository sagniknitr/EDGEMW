#!/bin/bash

run_gcc_tests() {
    rm -rf build/
    mkdir -p build/
    cd build/
    if [ "$1" = "clang" ] ; then
        cmake .. -DCONFIG_USE_CLANG=on
    else
        cmake ..
    fi

    make -j12
    cd ..

    ./build/TestExecutor
    sudo python ./testing/test_socket.py
    sudo python ./testing/test_logger.py
}

run_gcc_tests $1
