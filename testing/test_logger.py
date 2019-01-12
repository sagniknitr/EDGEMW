#!/usr/bin/python

import time
import os


os.system('./build/EdgeOSLogger')
os.system('./build/EdgeOSLogger -i 127.0.0.1 -p 4898 -f ./test &')
os.system('./build/loggerTest')
os.system('./build/loggerTest 127.0.0.1 4898 &')


char = 0

# let the comm happen and log
time.sleep(1);

os.system("killall EdgeOSLogger")
os.system("killall loggerTest")

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

time.sleep(1);

os.system("./build/nmeaTest ./lib/gpslib/src/tests/nmea_data/nmea_12_12_2018.txt")

os.system("./build/nmeaTest ./lib/gpslib/src/tests/nmea_data/nmea12_12_2018_2.txt")

os.system("./build/nmeaTest ./lib/gpslib/src/tests/nmea_data/nmea12_12_2018_2.txt")

os.system("./build/nmeaTest ./lib/gpslib/src/tests/nmea_data/nmea_12_12_2018_3.txt")

os.system("./build/nmeaTest ./lib/gpslib/src/tests/nmea_data/nmea_12_12_2018_4.txt")

exit(0)
