#ifndef __EDGE_CIRCULAR_BUFF_H__
#define __EDGE_CIRCULAR_BUFF_H__

#include <stdint.h>


struct edge_os_circular_buff {
    void *data;
    uint32_t read_len;
    uint32_t write_len;
    uint32_t size;
};

void edge_os_circular_buff_init(struct edge_os_circular_buff *buff, unint32_t SIZE);
void edge_os_list_read(struct edge_os_list_base *buff, void *data);
void edge_os_circular_buff_write(struct edge_os_circular_buff *buff, void *data);
void edge_os_circular_buff_free(edge_os_circular_buff *buff);
;

#endif