#!/bin/bash

run_gcc_tests() {
#    cd external/protobuf/
#    ./autogen.sh
#    ./configure
#    make -j12
#    sudo make install
#    sudo ldconfig

#    cd ../../

#    cd external/protobuf-c/
#    ./autogen.sh
#    ./configure
#    make -j12
#    sudo make install
#    sudo ldconfig

#    cd ../../

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

    sudo python ./testing/test_socket.py
    sudo python ./testing/test_logger.py
    ./build/TestExecutor list_test
    ./build/TestExecutor prng_test
    ./build/TestExecutor fsapi_test
    ./build/TestExecutor tokparse_test
    ./build/TestExecutor sysioctl_test
    ./build/TestExecutor pthread_test
    ./build/TestExecutor sched_test
    ./build/TestExecutor crypto_test
    ./build/TestExecutor config_parser_test ./tests/supervisor.conf
    ./build/TestExecutor config_parser_test
    ./build/TestExecutor dlist_test
    ./build/TestExecutor static_list_test
    ./build/TestExecutor stack_test
    ./build/TestExecutor queue_test
    ./build/TestExecutor fifo_test
    ./build/TestExecutor ssl_test server&
    ./build/TestExecutor ssl_test client&
    ./build/TestExecutor hashtbl_test
    #./build/TestExecutor msg_queue_test server /mq_test&
    #./build/TestExecutor msg_queue_test client /mq_test&
	./build/TestExecutor evtloop_test server&
	./build/TestExecutor evtloop_test client&
    ./build/TestExecutor rawsock_test
    sudo ./build/TestExecutor rawsock_test
	sleep 1
	echo "test complete.."
	exit 0
}

make_release() {
    rm -rf release/
    rm -rf build/
    mkdir -p build/
    cd build/
    if [ "$1" = "clang" ] ; then
        cmake .. -DCONFIG_RELEASE=on -DCONFIG_SHAREDLIB=on -DCONFIG_USE_CLANG=on
    else
        cmake .. -DCONFIG_RELEASE=on -DCONFIG_SHAREDLIB=on
    fi

    make -j12
    if [ "$?" -ne 0 ] ; then
        echo "failed to generate a release image.. check your tests"
        exit 1
    fi

    cd ..

    mkdir -p release/lib/
    mkdir -p release/inc/edgeos/

    # unstripped bin and lib
    cp -r build/libEdgeOS.a release/lib/
    cp -r build/EdgeOSLogger release/lib/

    # cp incls
    find ./lib/ -iname *.h | xargs -i cp {} release/inc/edgeos/
    find ./lib/ -iname *.hpp | xargs -i cp {} release/inc/edgeos/

    while read -r version
    do
        ver_str=$version;
    done < version.txt

    tar -zcvf edgeos_release-${ver_str}.tar release/
    sha1sum edgeos_release-${ver_str}.tar > release.sha1sum
}

if [ "$1" = "run_gcc_tests" ] ; then
    run_gcc_tests $1
elif [ "$1" = "make_release" ] ; then
    make_release $2
fi

