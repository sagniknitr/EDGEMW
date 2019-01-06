# EDGE OS - Lightweight Middleware distribution

[semaphore ci status](https://devnaga.semaphoreci.com/dashboards/my-work)

[![codecov](https://codecov.io/gh/DevNaga/EDGEMW/branch/master/graph/badge.svg)](https://codecov.io/gh/DevNaga/EDGEMW)

For planned features see [roadmap](roadmap.md)

## Features

Below are some of the features. More to come soon.


### Library interface

1. Framework for timers, sockets and signals - event Loop library

2. socket library API -
    1. UNIX and IPv4  TCP and UDP server and clients
    2. managed server abstraaction to reduce coding effort on user ende
    3. C++ abstraction to the TCP server and client with Socket library and the Eventloop

3. GPS parser library:
    1. for NMEA messages:
        `GPGGA`, `GPGSA`, `GPGSV`, `GPRMB`, `GPRMC`, `GPGGLL`

4. cryptography APIs - wrappers for most popular libraries (openssl, wolfssl, tomcrypt) - currently openssl
    1. hashing :
        `MD5`, `SHA`, `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`
    2. encryption and decryption:
        `AES-CBC-128`
        `AES-CBC-192`
        `AES-CBC-256`
        key generation and iv generation
    3. ECC sign and verify:
        `ECC-with-sha1`
        `ECC-with-sha256`
        curve support:
            `SECP256k1`,
            `SECP128r1`,
            `SECP224r1`,
            `brainpoolp224r1`,
            `brainpoolp256r1`,
        ECC keygen

5. Utilities -
    1. CSV File reader / writer / parser
    2. Token parser

6. algorithms -
    1. basic data structures for C
        linked list


### Services

1. Logger service
    1. remote logging, local logging yet to be done over unix domain
    2. log rotate - every 1 MB (configurable)


### how to compile

1. What the project uses (from source code):
    - protobuf-c - serialisation in C
    - openssl - for crypto interface


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

