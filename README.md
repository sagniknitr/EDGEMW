# EDGE OS - Lightweight Middleware distribution

[semaphore ci status](https://devnaga.semaphoreci.com/dashboards/my-work)

[![codecov](https://codecov.io/gh/DevNaga/EDGEMW/branch/master/graph/badge.svg)](https://codecov.io/gh/DevNaga/EDGEMW)

For planned features see [roadmap](roadmap.md)

## Features

Below are some of the features. More to come soon.


### Library interface

1. OS abstraction library for Linux
    1. Distributed publisher and subscriber system based on topics instead of ip address  - preliminary code
        1. topic based publish and subscription
        2. aim to achieve machine to machine communication with topic only
        3. topic collision and port assignments pending.
        4. different multicast ip partitioning 
2. Framework for timers, sockets and signals - event Loop library
3. socket library API -
    1. UNIX and IPv4  TCP and UDP server and clients
    2. C++ abstraction to the TCP server and client with Socket library and the Eventloop
4. GPS parser library - for NMEA messages: GPGGA, GPGSA, GPGSV, GPRMB, GPRMC, GPGGLL
5. Utilities -
    1. CSV File reader / writer / parser
    2. Token parser


### Services

1. Logger service
    1. remote logging, local logging yet to be done over unix domain


### how to compile

```bash
1. sudo apt install libprotobuf-c0-dev protobuf-c-compiler protobuf-compiler libprotobuf-dev libprotoc-dev libprotobuf-c-dev cmake make gcc g++ clang clang++
2. bash build.sh make_release # for gcc g++ builds

or 

2. bash build.sh make_release clang # for clang or clang ++ builds

```

the above will create a release folder in the `$(pwd)/EDGEMW/`. check the `release` folder for the release.

currently there is no cross `cmake` options for rpi, build directly on rpi for now.

### testing

1. more testing is required. right now each API is not passed really well through the codecov coverage. It needs to be elevated.
2. tested on x86-64 (server grade and notebook), ARM 32 bit machines (rpi) using ubuntu 16.04, 18.04 and rpi debian.
3. profiling tools are needed to profile parts of the API for end to end validation.

Below are some of the screenshots of the tests that are run on the current software WIP master.


![](tests/tcp_perf_test.png?raw=true)

