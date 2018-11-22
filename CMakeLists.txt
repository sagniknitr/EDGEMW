cmake_minimum_required(VERSION 2.8)

project(EDGEMW)

set(CMAKE_C_FLAGS "-O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC")

set(SOURCES
        common/evtloop/evtloop.c
        common/algorithms/list.c)


include_directories(
    common/evtloop/
    common/linux/net/
    remoteLog/
    common/algorithms/
    common/logger/
)

add_library(EdgeOS SHARED ${SOURCES})
