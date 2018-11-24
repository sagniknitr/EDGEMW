#include <stdio.h>
#include "circular_buff.h"


void edge_os_circular_buff_init(edge_os_circular_buff *buff, uint32_t size)
{

    buff = calloc(1,size*sizeof(edge_os_circular_buff));
    buff->max_size = size;
    edge_os_circular_buff_reset(buff);
}


void egde_os_circular_buff_reset(edge_os_circular_buff *buff)
{
    buff->read_len = 0;
    buff->write_len = 0;
    buff->max_size = 0;
}

void edge_os_circular_buff_free(edge_os_circular_buff *buff)
{
    assert(buff);
    free(buff);
}

void edge_os_circular_buff_write(edge_os_circular_buff *buff, void* data)
{
    buff->data[write_len] = data;
    buff->write_len = (buff->write_len + 1);
    edge_os_circular_buff_adjust(buff);
}

void edge_os_circular_buff_read(edge_os_circular_buff *buff, void* data)
{
    data = buff->data[read_len];
    edge_os_circular_buff_adjust(buff);
    buff->read_len = (buff->read_len + 1);
}

void edge_os_circular_buff_adjust(edge_os_circular_buff *buff)
{
    if (buff->write_len == max_size) {
        buff->write_len = 0;
    }
    else if(buff->read_len >= buff->write_len) {
        buff->read_len = buff->read_len % buff->max_size ; 
    }

}

