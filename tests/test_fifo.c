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

    pid = fork();
    if (pid == 0) {
        sleep(1); // lets wait for parent process to creat a fifo
        fd = edge_os_fifo_open("./test");

        while (1) {
            int ret;
            int val;

            ret = read(fd, &val, sizeof(val));
            if (ret <= 0) {
                break;
            }

            printf("from [parent process %d\n", val);
            if (val == 100 * 100) {
                break;
            }
        }
    } else {
        fd = edge_os_fifo_create("./test", 1024 * 1024);
        printf("%d\n", fd);

        int val = 0;

        while (1) {
            pid_t child;

            edge_os_nanosleep(1000 * 100);
            write(fd, &val, sizeof(val));
            val ++;

            child = waitpid(-1, NULL, WNOHANG);
            if (child == pid) {
                break;
            }
        }
    }

    return 0;
}

