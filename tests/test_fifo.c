#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <edgeos_fifo.h>
#include <edgeos_datetime.h>

int fifo_test(int argc, char **argv)
{
    pid_t pid;
    int fd;

    fd = edge_os_fifo_open(NULL);
    fd = edge_os_fifo_open("/root/test");

    pid = fork();
    if (pid == 0) {
        sleep(1); // lets wait for parent process to creat a fifo
        fd = edge_os_fifo_open("./test");

        while (1) {
            int ret;
            int val;

            ret = edge_os_fifo_read(fd, &val, sizeof(val));
            if (ret <= 0) {
                break;
            }

            printf("from [parent process %d\n", val);
            if (val == 100 * 100) {
                break;
            }
            edge_os_fifo_close(fd, NULL);
        }
    } else {
        fd = edge_os_fifo_create("./test", 0);
        printf("%d\n", fd);

        int val = 0;

        while (1) {
            pid_t child;
            int ret;

            edge_os_nanosleep(1000 * 100);
            ret = edge_os_fifo_write(fd, &val, sizeof(val));
            if (ret < 0) {
                break;
            }

            val ++;

            child = waitpid(-1, NULL, WNOHANG);
            if (child == pid) {
                break;
            }
        }
        edge_os_fifo_close(fd, "./test");
    }

    return 0;
}

