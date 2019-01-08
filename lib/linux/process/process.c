#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int edge_os_in_root()
{
    return geteuid();
}

