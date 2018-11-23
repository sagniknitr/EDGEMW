#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <distcom.h>

#define ERR_FAIL(__var) { \
    if (!__var) { \
        return -1; \
    } \
}

int main()
{
    void *dist;
    void *pub_node;

    dist = distcomm_init("127.0.0.1", 11214);
    ERR_FAIL(dist);

    pub_node = distcom_create_pub(dist, "/test");
    ERR_FAIL(pub_node);

    while (1) {
        distcomm_publish(pub_node, "hello", strlen("hello"));
        usleep(100 * 100);
    }
}
