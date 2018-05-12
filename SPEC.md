# SPECification

## principles

### allocation

1. use pre-allocated memory that's tunable or modifyable at runtime only once.
2. never allocate anything at run time / or use APIs that does this alloc. (`strdup` ..)

## service layer

### configuration manager

1. must provide a service layer for configuration management.
2. the service layer shall act one database thats minimal and can be used to set / get various data types including `int`, `double`, `float` and `string` objects.
3. must be fast and scale well.
4. allow UI to query for the configuration information via HTTP(s)..

### CLI

1. interface to the user for stats/ config / view / status 

### logger

1. allow logging to syslog (if available)
2. allow in-memory log
3. remote log - interface and service to a remote log on a linux machine
4. tooling interface for log display - via CLI

### system bus

1. master bus for all process communications
2. message queue system (but not linux mqueues) or a socket based `a -> proxy -> b`
3. services can get multicast packets on the bus for critical events (shutdown etc..)

### master system monitor

1. manages and startsup the system services in a dependency tree fashion
2. restarts if a system service crashes/ unrecoverable

## Libraries

### minimalistic event lib

1. use socket / epoll / pselect for sockets, timers, and signals
2. allow sending events to threads via `pthread_cond_signal` and wait via `pthread_cond_wait`.

### serialiser

1. serialisation API to communicate with in the system and outside the box

