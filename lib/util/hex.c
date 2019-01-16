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

void edge_os_hexdump_pretty(const char *str, uint8_t *buf, int buflen)
{
    int i;

    fprintf(stderr, "%s: \n", str);
    for (i = 0; i < buflen; i ++) {
        if (i != 0) {
            if (i % 8 == 0) {
                fprintf(stderr, "  ");
            }

            if (i % 16 == 0) {
                fprintf(stderr, "\n");
            }
        }
        fprintf(stderr, "%02x ", buf[i]);
    }
    fprintf(stderr, "\n");
}

