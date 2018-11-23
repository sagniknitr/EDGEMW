#!/usr/bin/python

import os


os.system('./build/EdgeOSLogger -i 127.0.0.1 -p 4898 -f ./test &')
os.system('./build/loggerTest 127.0.0.1 4898 &')


char = 0

# let the comm happen and log
os.sleep(10)

for f in os.listdir('.'):
    if os.path.isfile(f):
        if 'test' in f:
            fptr = open(f, 'r')
            for line in fptr:
                char = char + 1

if char != 0:
    exit(0)

exit(-1)
