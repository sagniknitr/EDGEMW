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

int edge_os_set_net_ipaddr(const char *ifname, const char *ip)
{
    edge_os_error("sysioctl: this function %s is currently not supported\n",
                                __func__);
    return -1;
}

int edge_os_get_hwaddr(const char *ifname, uint8_t *macaddr)
{
    if (!macaddr || !ifname) {
        edge_os_error("sysioctl: invalid macaddr or ifname @ %s %u\n",
                                        __func__, __LINE__);
        return -1;
    }

    int fd;
    int ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to open socket @ %s %u ",
                                        __func__, __LINE__);
        return -1;
    }

    struct ifreq ifr;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to ioctl @ %s %u ",
                                        __func__, __LINE__);
        goto bad;
    }

    void *ptr = ifr.ifr_hwaddr.sa_data;

    memcpy(macaddr, ptr, 6);

    close(fd);

    return 0;

bad:
    close(fd);

    return -1;
}

int edge_os_set_hwaddr(const char *ifname, const uint8_t *macaddr)
{
    edge_os_error("sysioctl: this function %s is currently not supported\n",
                                __func__);

    return -1;
}

int edge_os_is_mac_zero(const uint8_t *macaddr)
{
    uint8_t zmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (!macaddr)
        return -1;

    return memcmp(macaddr, zmac, 6);
}

int edge_os_is_mac_broadcast(const uint8_t *macaddr)
{
    uint8_t bmac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (!macaddr)
        return -1;

    return memcmp(macaddr, bmac, 6);
}

int edge_os_is_mac_multicast(const uint8_t *macaddr)
{
    if (!macaddr)
        return -1;

    uint8_t prefix[] = {0x01, 0x00, 0x5e};

    return ((macaddr[0] == prefix[0]) &&
            (macaddr[1] == prefix[1]) &&
            (macaddr[2] == prefix[2]));
}

#define EDGEOS_IFFLAGS_LO           0x01
#define EDGEOS_IFFLAGS_BROADCAST    0x02
#define EDGEOS_IFFLAGS_MUTLICAST    0x04
#define EDGEOS_IFFLAGS_UP           0x08

static int __edge_os_validate_ifflags(const char *ifname, int validate_flag)
{
    int fd;

    if (!ifname) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    int ret;

    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        goto bad;
    }

    close(fd);

    int opt = 0;



    if (validate_flag & EDGEOS_IFFLAGS_LO) {
        opt |= IFF_LOOPBACK;
    }

    if (validate_flag & EDGEOS_IFFLAGS_BROADCAST) {
        opt |= IFF_BROADCAST;
    }

    if (validate_flag & EDGEOS_IFFLAGS_MUTLICAST) {
        opt |= IFF_MULTICAST;
    }

    if (validate_flag & EDGEOS_IFFLAGS_UP) {
        opt |= IFF_UP;
    }

    return !!(ifr.ifr_flags & opt);

bad:
    close(fd);
    return -1;
}

int edge_os_is_if_lo(const char *ifname)
{
    return __edge_os_validate_ifflags(ifname, EDGEOS_IFFLAGS_LO);
}

int edge_os_is_if_broadcast(const char *ifname)
{
    return __edge_os_validate_ifflags(ifname, EDGEOS_IFFLAGS_BROADCAST);
}

int edge_os_is_if_multicast(const char *ifname)
{
    return __edge_os_validate_ifflags(ifname, EDGEOS_IFFLAGS_MUTLICAST);
}

int edge_os_is_if_up(const char *ifname)
{
    return __edge_os_validate_ifflags(ifname, EDGEOS_IFFLAGS_UP);
}

int __edge_os_set_ifflags(const char *ifname, int setflags)
{
    int fd;
    int ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct ifreq req;

    strcpy(req.ifr_name, ifname);

    ret = ioctl(fd, SIOCGIFFLAGS, &req);
    if (ret < 0) {
        goto bad;
    }

    if (setflags & EDGEOS_IFFLAGS_LO) {
        req.ifr_flags |= IFF_LOOPBACK;
    }

    if (setflags & EDGEOS_IFFLAGS_BROADCAST) {
        req.ifr_flags |= IFF_BROADCAST;
    }

    if (setflags & EDGEOS_IFFLAGS_MUTLICAST) {
        req.ifr_flags |= IFF_MULTICAST;
    }

    if (setflags & EDGEOS_IFFLAGS_UP) {
        req.ifr_flags |= IFF_UP;
    }

    ret = ioctl(fd, SIOCSIFFLAGS, &req);
    if (ret < 0) {
        goto bad;
    }

    close(fd);

    return 0;

bad:

    close(fd);
    return -1;
}

int edge_os_set_loopback(const char *ifname)
{
    return __edge_os_set_ifflags(ifname, EDGEOS_IFFLAGS_LO);
}

int edge_os_set_broadcast(const char *ifname)
{
    return __edge_os_set_ifflags(ifname, EDGEOS_IFFLAGS_BROADCAST);
}

int edge_os_set_multicast(const char *ifname)
{
    return __edge_os_set_ifflags(ifname, EDGEOS_IFFLAGS_MUTLICAST);
}

int edge_os_set_iface_up(const char *ifname)
{
    return __edge_os_set_ifflags(ifname, EDGEOS_IFFLAGS_UP);
}


int edge_os_get_mtu(const char *ifname)
{
    int ret;
    int fd;

    if (!ifname) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct ifreq req;

    strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFMTU, &req);
    if (ret < 0) {
        goto bad;
    }

    return req.ifr_mtu;

bad:
    close(fd);

    return -1;
}

int edge_os_get_netmask(const char *name, const char *mask)
{
    edge_os_error("sysioctl: this function %s is not implemented\n",
                            __func__);
    return -1;
}

