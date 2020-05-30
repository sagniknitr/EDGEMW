# EDGE OS - Lightweight Middleware distribution

[semaphore ci status]()


For planned features see [roadmap](roadmap.md)

## Features

see [features.md](features.md). More to come soon.


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

