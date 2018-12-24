cmake_minimum_required(VERSION 2.8)

project(EDGEMW)

set(CMAKE_C_FLAGS "-O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -fprofile-arcs -ftest-coverage -D_FORTIFY_SOURCE=2 -pg -fstack-usage -Wstack-usage=8192 -DCONFIG_UNIT_TESTS")
set(CMAKE_CXX_FLAGS "-std=c++11 -pg -fprofile-arcs -ftest-coverage -std=c++11 -DCONFIG_UNIT_TESTS -fstack-usage -Wstack-usage=8192")

set(SOURCES
        common/evtloop/evtloop.c
        common/algorithms/list.c
        common/linux/net/socket.c
        common/logger/edgeos_logger.c
        common/linux/shmem/shmem.c
        distcom/distcomm_pub.c
        common/linux/crypto/prng.c
        distcom/dist_sdp.c
        gpslib/src/nmea/nmea_parser.cpp
        common/util/csvparse.cpp
        common/init.c
        common/linux/file_system/fsapi.c
        common/util/tokenparse.c
        common/util/TokParse.cpp)

set(LIB_TEST_SOURCES
        common/tests/test_socket.c)

set(DISTCOMM_SOURCES
        distcom/master.c)

set(DIST_TEST_SOURCES
        common/tests/test_distcom.c)

set(NMEA_TEST_SOURCES
        gpslib/src/tests/unit_tests/unit_core.cpp)

set(TOK_PARSE_SOURCES
        common/tests/test_tokparse.cpp)

set(FSAPI_TEST_SOURCES
        common/tests/test_fsapi.cpp)

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
    distcom/
    common/
    gpslib/src/nmea/
    common/util/
    common/linux/file_system/
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

add_executable(tokTest ${TOK_PARSE_SOURCES})
target_link_libraries(tokTest pthread EdgeOS gcov)

add_executable(fsAPITests ${FSAPI_TEST_SOURCES})
target_link_libraries(fsAPITests pthread EdgeOS gcov)

