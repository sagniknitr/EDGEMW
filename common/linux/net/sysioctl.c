#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <edgeos_logger.h>
#include <linux/if.h>

int edgeos_get_net_ipaddr(const char *ifname, char *ip, int iplen)
{
    struct ifreq f;
    char *ipaddr;
    int fd;
    int ret;

    if (!ip || !ifname || (iplen <= 0)) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to socket @ %s %u ",
                                            __func__, __LINE__);
        return -1;
    }

    memset(&f, 0, sizeof(f));


    f.ifr_addr.sa_family = AF_INET;
    strncpy(f.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFADDR, &f);
    if (ret < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to ioctl @ %s %u ",
                                            __func__, __LINE__);
        goto bad;
    }

    ipaddr = inet_ntoa(((struct sockaddr_in *)&f.ifr_addr)->sin_addr);
    if (!ipaddr) {
        edge_os_error("sysioctl: failed to inet_ntoa @ %s %u\n",
                                            __func__, __LINE__);
        goto bad;
    }

    strncpy(ip, ipaddr, iplen - 1);

    close(fd);

    return 0;


bad:
    close(fd);
    return -1;
}

