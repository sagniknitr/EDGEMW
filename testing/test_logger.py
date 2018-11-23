#!/usr/bin/python

import time
import os


os.system('./EdgeOSLogger -i 127.0.0.1 -p 4898 -f ./test &')
os.system('./loggerTest 127.0.0.1 4898 &')


char = 0

# let the comm happen and log
time.sleep(10)

for f in os.listdir('.'):
    if os.path.isfile(f):
        if 'test' in f:
            fptr = open(f, 'r')
            for line in fptr:
                char = char + 1

os.system('./EOSTest')

exit(0)
