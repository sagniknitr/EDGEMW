#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <distcom.h>

#define ERR_FAIL(__var) { \
    if (!__var) { \
        return -1; \
    } \
}

void sub_callback(void *priv, void *data, int data_len)
{
    char *msg = data;

    printf("-> %s\n", msg);
}

int main(int argc, char **argv)
{
    int ret;
    void *dist;
    void *pub_node;
    void *sub_node;
    int publish_mode = 0;
    int sub_mode = 0;

    while ((ret = getopt(argc, argv, "ps")) != -1) {
        switch (ret) {
            case 'p':
                publish_mode = 1;
            break;
            case 's':
                sub_mode = 1;
            break;
        }
    }

    dist = distcomm_init("127.0.0.1", 12132);
    ERR_FAIL(dist);

    if (publish_mode) {
        pub_node = distcom_create_pub(dist, "/test");
        ERR_FAIL(pub_node);

        while (1) {
            distcomm_publish(pub_node, "hello", strlen("hello"));
            usleep(100 * 100);
        }
    } else if (sub_mode) {
        sub_node = distcom_create_sub(dist, "/test", sub_callback);
        ERR_FAIL(sub_node);

        distcomm_run(dist);
    }

    return 0;
}
