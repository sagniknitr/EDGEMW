#ifndef __EDGEOS_PRNG_H__
#define __EDGEOS_PRNG_H__

int edge_os_prng_init(char *prngdev);
int edge_os_prng_get_bytes(int fd, uint8_t *bytes, size_t len);
void edge_os_prng_deinit(int fd);

#endif
