#include <iostream>
#include <string>
#include <cstdint>
extern "C" {
#include <edgeos_msg_queue.h>
#include <edgeos_datetime.h>
}

int msg_queue_test(int argc, char **argv)
{
    void *q;

    printf("%s\n", argv[1]);
    if (std::string(argv[1]) == "server") {
        q = edge_os_mq_create(argv[2], 0, 0);
        if (!q) {
            return -1;
        }

        int count = 0;

        while (1) {
            int ret;
            char data[1024];

            count ++;

            uint32_t prio;

            ret = edge_os_mq_receive(q, data, sizeof(data), &prio);
            if (ret < 0) {
                return -1;
            }

            printf("msg_dequeued : %s : prio %d: count %d\n", data, prio, count);


            if (count > 100 * 1000) {
                break;
            }
        }
    } else {
        printf("client clode\n");
        q = edge_os_mq_open(argv[2]);
        if (!q) {
            return -1;
        }

        while (1) {
            char data[] = "hello";

            edge_os_mq_send(q, data, std::string(data).length(), 1);

            edge_os_nanosleep(10);
        }
    }

    return 0;
}

