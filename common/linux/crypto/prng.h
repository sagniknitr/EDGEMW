#ifndef __EDGEOS_PRNG_H__
#define __EDGEOS_PRNG_H__

/**
 * @brief - PRNG seeding initialisation
 *
 * @param prngdev - PRNG device name (Linux has /dev/urandom and QNX has /dev/random..
 *
 *          pass in NULL and the library takes care of which one to use for OS
 *
 * @return returns a file descriptor
 */
int edge_os_prng_init(char *prngdev);

/**
 * @brief - get bytes of given length len from the PRNG
 *
 * @param fd - return value of edge_os_prng_init
 * @param bytes - input buffer
 * @param len - length of input buffer
 *
 * @return returns 0 on success -1 on failure
 */
int edge_os_prng_get_bytes(int fd, uint8_t *bytes, size_t len);

/*
 * @brief - PRNG deinit
 *
 * @param - return value of edge_os_prng_init
 */
void edge_os_prng_deinit(int fd);

#endif

