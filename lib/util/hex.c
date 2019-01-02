#include <stdio.h>
#include <stdint.h>

void edge_os_hexdump(const char *str, uint8_t *buf, int buflen)
{
    int i;

    fprintf(stderr, "%s: ", str);
    for (i = 0; i < buflen; i ++)
        fprintf(stderr, "%02x", buf[i] & 0xff);
    fprintf(stderr, "\n");
}


