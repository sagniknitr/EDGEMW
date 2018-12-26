cmake_minimum_required(VERSION 2.8)

project(EDGEMW)

option(CONFIG_USE_CLANG "test with clang / clang++" off)
option(CONFIG_RELEASE off)

set(OS_FLAGS "-DOS_LINUX")

if (CONFIG_USE_CLANG)
    message("using clang..")
    set(CMAKE_C_COMPILER "clang")
    set(CMAKE_C_FLAGS "-Wall -Weverything ${OS_FLAGS}")
    set(CMAKE_CXX_COMPILER "clang++")
    set(CMAKE_CXX_FLAGS "-Wall -std=c++11 -Weverything ${OS_FLAGS}")
else()
    message("using gcc..")
    set(CMAKE_C_COMPILER "gcc")

    if (CONFIG_RELEASE)
        set(CMAKE_C_FLAGS "-O3 -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -D_FORTIFY_SOURCE=2 ${OS_FLAGS}")
        set(CMAKE_CXX_FLAGS "-O3 -Wall -Wextra -Werror -Wno-unused-parameter -Wshadow -fPIC -fPIE -std=c++11 ${OS_FLAGS}")
    else()
        set(CMAKE_C_FLAGS "-O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -fprofile-arcs -ftest-coverage -D_FORTIFY_SOURCE=2 -pg -DCONFIG_UNIT_TESTS ${OS_FLAGS}")
        set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wshadow -fPIC -fPIE -std=c++11 -pg -fprofile-arcs -ftest-coverage -pg -std=c++11 -DCONFIG_UNIT_TESTS ${OS_FLAGS}")
    endif()

    set(CMAKE_CXX_COMPILER "g++")

endif()

set(SOURCES
        common/evtloop/evtloop.c
        common/algorithms/list.c
        common/linux/net/socket.c
        common/logger/edgeos_logger.c
        common/linux/shmem/shmem.c
        distcom/distcomm_pub.c
        common/linux/crypto/prng.c
        common/util/errormsg.c
        distcom/dist_sdp.c
        gpslib/src/nmea/nmea_parser.cpp
        common/util/csvclass.cpp
        common/init.c
        common/linux/file_system/fsapi.c
        common/util/tokenparse.c
        common/util/TokParse.cpp
        common/linux/net/TcpServer.cpp
        common/linux/net/ClientMgr.cpp
        common/linux/sched/sched.c)

set(LIB_TEST_SOURCES
        tests/test_socket.c)

set(DISTCOMM_SOURCES
        distcom/master.c)

set(DIST_TEST_SOURCES
        tests/test_distcom.c)

set(NMEA_TEST_SOURCES
        gpslib/src/tests/unit_tests/unit_core.cpp)

set(EVTLOOP_TEST_SOURCES
        tests/test_evtloop.cpp)

set(TCPSERVER_TEST_SOURCES
        tests/test_TcpServer.cpp)

set(TEST_CASES_SOURCES
        tests/test_framework.cpp
        tests/test_fsapi.cpp
        tests/test_tokparse.cpp
        tests/test_list.c
        tests/test_prng.c)

set(TRANSFER_TEST_SOURCES
        tests/transfer_test.c)
        
include_directories(
    common/evtloop/
    common/linux/net/
    remoteLog/
    common/algorithms/
    common/logger/
    common/linux/net/
    common/linux/shmem/
    common/linux/transport/
    common/linux/crypto/
    common/incl/
    distcom/
    common/
    gpslib/src/nmea/
    common/util/
    common/linux/file_system/
    common/linux/sched/
)

add_library(EdgeOS ${SOURCES})
target_link_libraries(EdgeOS pthread rt gcov)

add_executable(EdgeOSLogger logsrv/edgeos_logsrv.cpp)
target_link_libraries(EdgeOSLogger pthread EdgeOS gcov rt)

add_executable(loggerTest logsrv/tests/logsrv_test.c)
target_link_libraries(loggerTest pthread EdgeOS gcov)

#add_executable(shmTransport common/linux/transport/controller.c)
#target_link_libraries(shmTransport pthread EdgeOS gcov)

add_executable(distCommMaster ${DISTCOMM_SOURCES})
target_link_libraries(distCommMaster pthread EdgeOS gcov)

add_executable(EOSTest ${LIB_TEST_SOURCES})
target_link_libraries(EOSTest pthread EdgeOS gcov)

add_executable(DistTest ${DIST_TEST_SOURCES})
target_link_libraries(DistTest pthread EdgeOS gcov)

add_executable(nmeaTest ${NMEA_TEST_SOURCES})
target_link_libraries(nmeaTest pthread EdgeOS gcov)

add_executable(ELTest ${EVTLOOP_TEST_SOURCES})
target_link_libraries(ELTest pthread EdgeOS gcov)

add_executable(TcpServerTest ${TCPSERVER_TEST_SOURCES})
target_link_libraries(TcpServerTest pthread EdgeOS gcov)

add_executable(TestExecutor ${TEST_CASES_SOURCES})
target_link_libraries(TestExecutor pthread EdgeOS gcov)

add_executable(TransferTest ${TRANSFER_TEST_SOURCES})
target_link_libraries(TransferTest pthread EdgeOS gcov)
