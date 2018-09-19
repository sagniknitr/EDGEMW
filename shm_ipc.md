# Architecture

This architecture describe the Shared memory based IPC in the userspace in linux system between any two processes.

The architecture consists of n number of processes communicating with each other via shared memory conectionless. There are two paths
to this protocol. One is data path where access / transactions can happen and another is control path where a lock and unlock
is used to protect the shared memory. For this simple linux file locks are used to alleviate the disadvantage of copying
data inside the kernel level. The idea of the locks is to have a read/write locks so that the readers can access in parallel
as soon as writer releases lock.

## Design

1. Each process is assumed to be either a porducer or a consumer of the data
2. Producer creates a file lock (fcntl syscall) and allocates a shared memory block or group of blocks (usually associate a block with a file lock for faster access by consumer)
3. Consumer then opens to the file lock based on a simple discovery protocol described below..
4. writing the data into the shared memory:
  4.1. producer takes a write lock with fctnl on the file, this keep the readers wiaiting
  4.2. producer writes the data and unlocks
  4.3. in future, producer may over write the content and thus the data lifetime in the shared memory is not guaranteed
5. reading the data from the shared memory:
  5.1. reader(or readers) take a read lock with fcntl on the file, this keeps the writer waiting till they finish
  5.2. reader consumes or copies data into its local memory
  5.3. reader unlocks
  
## advantages

1. locksing is guaranteed at the kernel level till all readers are done the writer will not be woken up
2. only locking is done and no transfer via file is done, causing only control paths in the kernel execute and no copies
3. user space process to process memcpy of shared memory done - this is the fastest compared to copying in to the kernel space using sockets

## Discovery protocol

The design assumes that the implementer writes a library API and thus

1. the library is assumed to be creating a set of locks under a private directory that is known to the library such as /var/
2. when a client opens a lock file, the lock filename is seaerched for in the /var/ and if found then the lock will be opened or else
   an error is returned
