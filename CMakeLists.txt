cmake_minimum_required(VERSION 2.8)

project(EDGEMW)

set(SOURCES common/evtloop/evtloop.cpp)
include_directories(
    common/evtloop/
)

add_library(EdgeOS SHARED ${SOURCES})
