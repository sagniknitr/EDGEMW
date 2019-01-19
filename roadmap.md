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
    4. client application for monitoring and stats

2. CLI for EDGE OS services
    1. remote monitoring via a simple console

3. System export:
    1. cpu usage, memory and resource limits expose over a network socket to backend managemnt over protobuf
    2. diagnosis for each service

4. Config parser:
    1. XML configuration parsing
    2. ini configuraiton parsing
    3. json configuration parsing

5. Algorithms:
    1. Data structures:
        1. Circular Q
        2. Sliding Window
        3. timeout based Sliding window buffer manager, hash TBL and other ds
        4. circular doubly linked lists
        5. circular lists
        6. binary tree

6. File systems
    1. support sync and async features when CPU in idling mode
    2. watching the files with inotify and notifying it to the corresponding registered callbak
    3. unix domain socket interface support for `LogSrv`
    4. packet logger based on libpcap header format - for reduced memory foot print
    5. packet reader based on libpcap header format - for reduced memory foot print

7. Thread pools
    1. worker threads independent of the evtloop - thread scheduling
    2. make scheduling of work for each worker thread work!

8. Networking
    1. raw socket API - sender, and receiver, with ether_header, iphdr, udphdr, tcphdr, tuntap
    2. ipv6 support - send, recv, create, delete, name to ip
    3. extend network layer for all purposes - v6 support, raw socket and splices for large payload transmit and receive
    4. wireless ioctl and wireless 802.11 packet parsing and packing
    5. tools to perform arp poisoning (only for learning), arp poison detection
    6. reverse ARP API

9. Databases
    1. interface with SQL database

10. Bluetooth interface
    1. with HCI library
    2. bluetooth low energy component

11. performance profiler interface library

12. telemetry service
    1. send telemetry info
        1. realtime - cpu load, memory, bandwidth usage for each radio, network hardware (packets sent and received)
        2. non realtime

13. communications
    1. d-bus system bus interfacing
    2. shared memory based communication

## minor features

1. add ublox protocol support GPS

one last but important feature is to support C++ class interfaces to the library API.

