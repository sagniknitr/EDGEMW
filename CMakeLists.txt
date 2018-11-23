cmake_minimum_required(VERSION 2.8)

project(EDGEMW)

set(CMAKE_C_FLAGS "-O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -fprofile-arcs -ftest-coverage")
set(CMAKE_CXX_FLAGS "-std=c++11 -fprofile-arcs -ftest-coverage")

set(SOURCES
        common/evtloop/evtloop.c
        common/algorithms/list.c
        common/linux/net/socket.c
        common/logger/edgeos_logger.c
        common/linux/shmem/shmem.c)


include_directories(
    common/evtloop/
    common/linux/net/
    remoteLog/
    common/algorithms/
    common/logger/
    common/linux/net/
    common/linux/shmem/
    common/linux/transport/
)

add_library(EdgeOS SHARED ${SOURCES})
target_link_libraries(EdgeOS pthread rt gcov)

add_executable(EdgeOSLogger logsrv/edgeos_logsrv.cpp)
target_link_libraries(EdgeOSLogger pthread gcov)

add_executable(loggerTest logsrv/tests/logsrv_test.c)
target_link_libraries(loggerTest pthread EdgeOS gcov)

add_executable(shmTransport common/linux/transport/controller.c)
target_link_libraries(shmTransport pthread EdgeOS gcov)
