## roadmap

This serves a plan for new features and fixes planned.

1. testing testing testing and automation of major portion of software - get 99 coverage

## major plan

the below list is based on the capture most commonly used calls to general algorithms / system calls / optimisations so that a project can be kickstarted quick without rewriting them again and again. Right now this only supports linux, but plans to support QNX as well for OS abstraction.

Right now testing is only done with in Travis with Linux, X86 architecture (mostly 64 bits) - free opensource tier.

1. supervisor service
    1. monitor and restart specific services with in the system
    2. dynamic monitoring register and unregister (protobuf)
    3. periodic update from each process via unix domain udp

2. CLI for EDGE OS services
    1. remote monitoring via a simple console

3. System export:
    1. cpu usage, memory and resource limits expose over a network socket to backend managemnt over protobuf
    2. diagnosis for each service

4. Util:
    1. safe string to integer, double and other type conversion API and reverse - done

5. Config parser:
    1. Variable = Value type configuration parsing
    2. XML configuration parsing
    3. ini configuraiton parsing

6. Algorithms:
    1. Data structures:
        1. DLL
        2. HashTBL
        3. Circular Q
        4. Sliding Window
        5. timeout based Sliding window buffer manager, hash TBL and other ds

7. File systems
    1. use MMAP for larger file seeks, writes and reads
    2. support sync and async features when CPU in idling mode
    3. watching the files with inotify and notifying it to the corresponding registered callbak
    4. unix domain socket interface support for `LogSrv`

8. Thread pools
    1. worker threads independent of the evtloop - thread scheduling

9. Networking
    1. raw socket API - with ether_header, iphdr, udphdr, tcphdr

## minor features

1. extend network layer for all purposes - v6 support, raw socket and splices for large payload transmit and receive
2. add ublox protocol support GPS

one last but important feature is to support C++ class interfaces to the library API.

