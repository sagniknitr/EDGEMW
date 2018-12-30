#ifndef __EDGE_DISTCOM_H__
#define __EDGE_DISTCOM_H__

void* distcomm_init(char *master_addr, int master_port);
void* distcom_create_pub(void *ctx, char *pubname);
int distcomm_publish(void *ctx, void *msg, int msglen);
void* distcom_create_sub(void *ctx, char *subname, void (sub_callback)(void *priv_ptr, void *data, int data_len));
void distcomm_run(void *ctx);



#endif
