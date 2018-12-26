#!/usr/bin/python

import os


# +ve

os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -t -U -s -C 1000')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -t -U -s -C 10')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -t -s -C 1000')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -t -s -C 10')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -t -c')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -t -U -c')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -u -s')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -u -c')
os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -u -U -c')
os.system('./build/EOSTest -i 127.0.0.1 -s -u -U')



# -ve

os.system('./build/EOSTest -i 127.0.0.1 -p 4898 -t -s -C -10')

