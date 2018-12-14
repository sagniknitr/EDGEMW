#!/usr/bin/python

import time
import os


os.system('./build/EdgeOSLogger -i 127.0.0.1 -p 4898 -f ./test &')
os.system('./build/loggerTest 127.0.0.1 4898 &')


char = 0

# let the comm happen and log
time.sleep(10)

for f in os.listdir('.'):
    if os.path.isfile(f):
        if 'test' in f:
            fptr = open(f, 'r')
            for line in fptr:
                char = char + 1

os.system('./build/EOSTest')

os.system('./build/distCommMaster&')
os.system('./build/DistTest -p&')
os.system('./build/DistTest -s&')

time.sleep(10);

exit(0)
