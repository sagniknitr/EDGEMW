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

        set(CMAKE_C_FLAGS "-O3 -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -D_FORTIFY_SOURCE=2 -DWC_NO_HARDEN -DCONFIG_CRYPTO_LIB_OPENSSL ${OS_FLAGS}")
        set(CMAKE_CXX_FLAGS "-O3 -Wall -Wextra -Werror -Wno-unused-parameter -Wshadow -fPIC -fPIE -std=c++11 -DWC_NO_HARDEN -DCONFIG_CRYPTO_LIB_OPENSSL ${OS_FLAGS}")

    else()

        set(CMAKE_C_FLAGS "-O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -fprofile-arcs -ftest-coverage -D_FORTIFY_SOURCE=2 -DWC_NO_HARDEN -DCONFIG_CRYPTO_LIB_OPENSSL -pg ${OS_FLAGS}")
        set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wno-unused-parameter -Wshadow -fPIC -fPIE -std=c++11 -pg -fprofile-arcs -ftest-coverage -pg -std=c++11 -DWC_NO_HARDEN -DCONFIG_CRYPTO_LIB_OPENSSL ${OS_FLAGS}")

    endif()

    set(CMAKE_CXX_COMPILER "g++")

endif()

set(SOURCES
        lib/evtloop/evtloop.c
        lib/algorithms/list.c
        lib/linux/net/socket.c
        lib/logger/edgeos_logger.c
        lib/linux/shmem/shmem.c
        lib/logger/logger.c
        services/distcom/distcomm_pub.c
        lib/linux/crypto/prng.c
        services/distcom/dist_sdp.c
        lib/gpslib/src/nmea/nmea_parser.cpp
        lib/util/csvclass.cpp
        lib/init.c
        lib/linux/file_system/fsapi.c
        lib/util/tokenparse.c
        lib/util/TokParse.cpp
        lib/linux/net/TcpServer.cpp
        lib/linux/net/ClientMgr.cpp
        lib/linux/sched/sched.c
        lib/linux/net/sysioctl.c
        lib/linux/pthreads/pthreads.c
        lib/linux/net/ds/generated/dist_sdp.pb-c.c
        lib/util/conv.c
        lib/crypto/crypto.c
        lib/util/hex.c)

set(LIB_TEST_SOURCES
        tests/test_socket.c)

set(DISTCOMM_SOURCES
        services/distcom/master.c)

set(DIST_TEST_SOURCES
        tests/test_distcom.c)

set(NMEA_TEST_SOURCES
        lib/gpslib/src/tests/unit_tests/unit_core.cpp)

set(EVTLOOP_TEST_SOURCES
        tests/test_evtloop.cpp)

set(TCPSERVER_TEST_SOURCES
        tests/test_TcpServer.cpp)

set(TEST_CASES_SOURCES
        tests/test_framework.cpp
        tests/test_fsapi.cpp
        tests/test_tokparse.cpp
        tests/test_list.c
        tests/test_prng.c
        tests/test_sysioctl.c
        tests/test_pthread.c
        tests/test_crypto.c)

set(TRANSFER_TEST_SOURCES
        tests/transfer_test.c)

set(DS_SOURCES
        lib/linux/net/ds/controller.c)

SET(DS_SAMPLE_SOURCES
        lib/linux/net/ds/sample.c)
        
include_directories(
    lib/evtloop/
    lib/linux/net/
    remoteLog/
    lib/algorithms/
    lib/logger/
    lib/linux/net/
    lib/linux/shmem/
    lib/linux/transport/
    lib/linux/crypto/
    lib/incl/
    services/distcom/
    lib/
    lib/gpslib/src/nmea/
    lib/util/
    lib/linux/file_system/
    lib/linux/sched/
    lib/linux/pthreads/
    lib/linux/net/ds/
    lib/linux/net/ds/generated/
    services/supervisor/
    services/ota/
    lib/crypto/
)

SET(SUPERVISOR_SOURCES
        services/supervisor/supervisor.c)

SET(OTA_SOURCES
        services/ota/ota.c)

add_library(EdgeOS ${SOURCES})
target_link_libraries(EdgeOS pthread rt gcov protobuf-c crypto ssl)

add_executable(EdgeOSLogger services/logsrv/edgeos_logsrv.cpp)
target_link_libraries(EdgeOSLogger pthread EdgeOS gcov rt)

add_executable(loggerTest services/logsrv/tests/logsrv_test.c)
target_link_libraries(loggerTest pthread EdgeOS gcov)

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
target_link_libraries(TestExecutor pthread EdgeOS gcov crypto ssl)

add_executable(TransferTest ${TRANSFER_TEST_SOURCES})
target_link_libraries(TransferTest pthread EdgeOS gcov)

add_executable(DsController ${DS_SOURCES})
target_link_libraries(DsController pthread EdgeOS gcov protobuf-c)

add_executable(DsSample ${DS_SAMPLE_SOURCES})
target_link_libraries(DsSample pthread EdgeOS gcov protobuf-c)

add_executable(EdgeOSSupervisor ${SUPERVISOR_SOURCES})
target_link_libraries(EdgeOSSupervisor pthread EdgeOS gcov protobuf-c)

add_executable(EdgeOSOTA ${OTA_SOURCES})
target_link_libraries(EdgeOSOTA pthread EdgeOS gcov protobuf-c)

