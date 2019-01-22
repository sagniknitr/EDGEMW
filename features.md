# Features

Here are some of the features of the EDGEOS middleware library and its Services.

The EDGEOS middleware library can be compilable for a small embeddded system (RPI), or to an automotive hardware (with YOCTO).

Below are some of the features

## services

1. Logging service

## Library

## Framework

1. Event Framework that contain **timers**, **sockets** and **Signals**
2. Thread pools and worker setup and scheduling

## Algorithms:

1. Linked lists
2. Doubly linked lists
3. Static lists - for smaller embedded systems
4. Stack
5. Queue

## GPS library

1. NMEA parser: supports `GPGGA`, `GPGSA`, `GPGSV`, `GPRMB`, `GPGLL`, `GPRMC`.

## Networking Library:

1. TCP, UDP server and client API
2. UNIX domain server and client API
3. Managed server for both TCP, UDP and UNIX
4. RAW socket interfaces

## Cryptography

1. AES - with 128, 192 and 256 keys
    1. CBC mode
    2. key generation

2. ECDSA
    1. signing and verification
    2. with supported curves: `secp256k1`, `secp128r1`, `secp128r2`, `secp224r1`, `secp224r2`, `secp224k1`, `secp160k1`, `secp160r1`, `secp160r2`, `secp192k1`, `brainpoolp224r1`, `brainpoolp256r1`
    3. ECC key generation with above supported curves

## utility library API

1. CSV read/ write file or buffer
2. Token parser
3. configuration parser
    1. variable = value; type of configuration file parser




