#!/bin/bash

./configd ## no config file .. so error cases execute
./configd -t -f ./cfgd/config.ds  ## positive cases execute
