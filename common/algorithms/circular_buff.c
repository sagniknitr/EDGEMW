#include <stdio.h>
#include "circular_buff.h"


int  edge_os_circular_buff_init(struct edge_os_circular_buff *buff, uint32_t size)
{

    buff = calloc(1,size*sizeof(struct edge_os_circular_buff));
    if (!buff) {
        return -1;
    }
    buff->max_size = size;
    edge_os_circular_buff_reset(buff);
    return 1;
}


void egde_os_circular_buff_reset(struct edge_os_circular_buff *buff)
{
    buff->read_len = 0;
    buff->write_len = 0;
    buff->max_size = 0;
}

void edge_os_circular_buff_free(struct edge_os_circular_buff *buff)
{
    assert(buff);
    free(buff);
}

void edge_os_circular_buff_write(struct edge_os_circular_buff *buff, void* data)
{
    buff->data[buff->write_len] = data;
    buff->write_len = (buff->write_len + 1);
    edge_os_circular_buff_adjust(buff);
}

void edge_os_circular_buff_read(struct edge_os_circular_buff *buff, void* data)
{
    data = buff->data[buff->read_len];
    edge_os_circular_buff_adjust(buff);
    buff->read_len = (buff->read_len + 1);
}

void edge_os_circular_buff_adjust(struct edge_os_circular_buff *buff)
{
    if (buff->write_len == buff->max_size) {
        buff->write_len = 0;
    }
    else if(buff->read_len >= buff->write_len) {
        buff->read_len = buff->read_len % buff->max_size ; 
    }

}

