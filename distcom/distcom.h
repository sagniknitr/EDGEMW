#ifndef __EDGE_DISTCOM_H__
#define __EDGE_DISTCOM_H__

void* distcomm_init(char *master_addr, int master_port);
void* distcom_create_pub(void *ctx, char *pubname);
int distcomm_publish(void *ctx, void *msg, int msglen);



#endif
