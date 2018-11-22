cmake_minimum_required(VERSION 2.8)

project(EDGEMW)

set(CMAKE_C_FLAGS "-O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC")
set(CMAKE_CXX_FLAGS "-std=c++11")

set(SOURCES
        common/evtloop/evtloop.c
        common/algorithms/list.c
        common/linux/net/socket.c
        common/logger/edgeos_logger.c)


include_directories(
    common/evtloop/
    common/linux/net/
    remoteLog/
    common/algorithms/
    common/logger/
    common/linux/net/
)

add_library(EdgeOS SHARED ${SOURCES})

add_executable(EdgeOSLogger logsrv/edgeos_logsrv.cpp)
target_link_libraries(EdgeOSLogger pthread)

add_executable(loggerTest logsrv/tests/logsrv_test.c)
target_link_libraries(loggerTest pthread EdgeOS)