#include <stdio.h>
#include <circular_buff.h>


void edge_os_circular_buff_init(edge_os_circular_buff *buff, uint32_t size)
{

    buff = malloc(sizeof(edge_os_circular_buff));
    edge_os_circular_buff_reset(buff);
}


void egde_os_circular_buff_reset(edge_os_circular_buff *buff)
{
    buff->read_len = 0;
    buff->write_len = 0;
    buff->full = false;
}

void edge_os_circular_buff_free(edge_os_circular_buff *buff)
{
    assert(buff);
    free(buff);
}