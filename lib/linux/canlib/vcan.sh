#!/bin/bash

# Enable vcan0 simulated interface

# as root..

modprobe can
modprobe vcan
modprobe slcan

ip link add name vcan0 type vcan
ifconfig vcan0 up

