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


Below are some of the screenshots of the tests that are run on the current software WIP master.

![](tests/tcp_perf_test.png?raw=true)

