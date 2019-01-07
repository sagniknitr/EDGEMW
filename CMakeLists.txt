cmake_minimum_required(VERSION 2.8)

project(EDGEMW)

# command line
option(CONFIG_USE_CLANG "test with clang / clang++" off)
option(CONFIG_RELEASE off)
option(CONFIG_SHAREDLIB off)

set(OS_FLAGS "-DOS_LINUX")

if (CONFIG_USE_CLANG)
    message("using clang..")
    set(CMAKE_C_COMPILER "clang")
    set(CMAKE_C_FLAGS "-Wall -Weverything ${OS_FLAGS} -DCONFIG_CRYPTO_LIB_OPENSSL")
    set(CMAKE_CXX_COMPILER "clang++")
    set(CMAKE_CXX_FLAGS "-Wall -std=c++11 -Weverything ${OS_FLAGS} -DCONFIG_CRYPTO_LIB_OPENSSL")
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

SET(ALG_SOURCES
        lib/algorithms/list.c)

SET(LINUX_SPEC_SOURCES
        lib/linux/net/socket.c
        lib/linux/shmem/shmem.c
        lib/linux/crypto/prng.c
        lib/linux/file_system/fsapi.c
        lib/linux/net/TcpServer.cpp
        lib/linux/net/ClientMgr.cpp
        lib/linux/sched/sched.c
        lib/linux/net/sysioctl.c
        lib/linux/pthreads/pthreads.c
        lib/linux/net/ds/generated/dist_sdp.pb-c.c
        lib/linux/date_time/date_time.c
        lib/linux/process/process.c)

SET(UTIL_SOURCES
        lib/util/csvclass.cpp
        lib/util/tokenparse.c
        lib/util/TokParse.cpp
        lib/util/conv.c
        lib/util/hex.c)

SET(CRYPTO_SOURCES
        lib/crypto/crypto.c)

SET(GPSLIB_SOURCES
        lib/gpslib/src/nmea/nmea_parser.cpp)

SET(CONFIG_PARSER_SOURCES
        lib/config/config_parser.c
        lib/config/config_parser.cpp)

set(SOURCES
        lib/evtloop/evtloop.c
        ${ALG_SOURCES}
        lib/logger/edgeos_logger.c
        ${LINUX_SPEC_SOURCES}
        ${UTIL_SOURCES}
        lib/logger/logger.c
        services/distcom/distcomm_pub.c
        services/distcom/dist_sdp.c
        ${GPSLIB_SOURCES}
        ${CRYPTO_SOURCES}
        lib/init.c
        ${CONFIG_PARSER_SOURCES})

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
        tests/test_crypto.c
        tests/test_sched.c)

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
    lib/config/
    lib/linux/date_time/
    lib/linux/process/
    services/cli/
    services/cli/library/)

SET(SUPERVISOR_SOURCES
        services/supervisor/supervisor.c)

SET(TEST_SUPERVISOR_SOURCES
        services/supervisor/test_supervisor.c)

SET(OTA_SOURCES
        services/ota/ota.c)

SET(CLI_SERVICE_SOURCES
        services/cli/backend.c)

SET(CLI_CLIENT_SOURCES
        services/cli/commands.c
        services/cli/database.c
        services/cli/library/show_callback.c
        services/cli/rpc.c)

add_library(EdgeOS STATIC ${SOURCES})

if (CONFIG_SHAREDLIB)
    add_library(EdgeOSShared SHARED ${SOURCES})
    target_link_libraries(EdgeOSShared pthread rt gcov protobuf-c crypto ssl)
endif()

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

add_executable(SupervisorTest ${TEST_SUPERVISOR_SOURCES})
target_link_libraries(SupervisorTest pthread EdgeOS gcov protobuf-c crypto)

add_executable(EdgeOSOTA ${OTA_SOURCES})
target_link_libraries(EdgeOSOTA pthread EdgeOS gcov protobuf-c)

add_executable(EdgeOSCLId ${CLI_SERVICE_SOURCES})
target_link_libraries(EdgeOSCLId pthread EdgeOS gcov protobuf-c)

add_executable(EdgeOSCLI ${CLI_CLIENT_SOURCES})
target_link_libraries(EdgeOSCLI pthread EdgeOS gcov protobuf-c)

