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
#include <ifaddrs.h>
#include <edgeos_ioctl.h>

static void __edge_os_get_netdev_info(struct edge_os_iflist *t,
                                      struct ifaddrs *it)
{
    int valid_ip = 0;

    strcpy(t->ifname, it->ifa_name);

    if (it->ifa_flags & IFF_BROADCAST)
        t->has_broadcast_set = 1;

    if (it->ifa_flags & IFF_UP)
        t->if_up = 1;

    if (it->ifa_flags & IFF_MULTICAST)
        t->has_mcast_set = 1;

    if (it->ifa_flags & IFF_LOOPBACK)
        t->is_loopback = 1;

    struct edge_os_ipaddr_set *i = NULL;

    if (it->ifa_addr) {
        const char *ret;

        i = calloc(1, sizeof(struct edge_os_ipaddr_set));
        if (!t) {
            return;
        }

        if (it->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *ip;

            ip = (struct sockaddr_in *)(it->ifa_addr);

            ret = inet_ntop(AF_INET, &(ip->sin_addr.s_addr),
                                i->ipaddr, sizeof(i->ipaddr));
            if (!ret) {
                return;
            }
            valid_ip = 1;
        } else if (it->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *ip6;

            ip6 = (struct sockaddr_in6 *)(it->ifa_addr);

            ret = inet_ntop(AF_INET6, &ip6->sin6_addr.s6_addr,
                                i->ipaddr, sizeof(i->ipaddr));
            if (!ret) {
                return;
            }
            valid_ip = 1;
        } else {
            valid_ip = 0;
            free(i);
            return;
        }
    }

    if (valid_ip) {
        if (!t->set) {
            t->set = i;
        } else {
            struct edge_os_ipaddr_set *j;

            j = t->set;
            while (j->next) {
                j = j->next;
            }
            j->next = i;
        }
    }
}

struct edge_os_iflist *edge_os_get_netdev_info()
{
    struct ifaddrs *ifaddr;
    struct ifaddrs *it;
    int ret;

    ret = getifaddrs(&ifaddr);
    if (ret < 0) {
        return NULL;
    }

    struct edge_os_iflist *s = NULL;
    struct edge_os_iflist *tail = NULL;

    for (it = ifaddr; it;  it = it->ifa_next) {
        struct edge_os_iflist *t;
        struct edge_os_iflist *f;

        for (f = s; f; f = f->next) {
            if (!strcmp(it->ifa_name, f->ifname)) {
                break;
            }
        }

        if (!f) {
            t = calloc(1, sizeof(struct edge_os_iflist));
            if (!t) {
                goto bad;
            }

            t->set = NULL;

            __edge_os_get_netdev_info(t, it);

            if (!s) {
                s = t;
                tail = t;
            } else {
                tail->next = t;
                tail = t;
            }
        } else {
            __edge_os_get_netdev_info(f, it);
        }
    }

    freeifaddrs(ifaddr);
    return s;

bad:
    freeifaddrs(ifaddr);
    return NULL;
}

void edge_os_free_netdev_info(struct edge_os_iflist *dev)
{
    struct edge_os_iflist *t;
    struct edge_os_iflist *t1;

    t = t1 = dev;

    while (t) {
        t1 = t;
        t = t->next;

        struct edge_os_ipaddr_set *i;
        struct edge_os_ipaddr_set *i1;

        i = i1 = t1->set;

        while (i) {
            i1 = i;
            i = i->next;
            free(i1);
        }

        free(t1);
    }
}

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
        edge_os_error("sysioctl: invalid ifname ptr %p @ %s %u\n",
                                ifname, __func__, __LINE__);
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to socket ");
        return -1;
    }

    int ret;

    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to ioctl ");
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

    if (!ifname) {
        edge_os_error("sysioctl: invalid ifname ptr %p @ %s %u\n",
                            ifname, __func__, __LINE__);
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to socket ");
        return -1;
    }

    struct ifreq req;

    strcpy(req.ifr_name, ifname);

    ret = ioctl(fd, SIOCGIFFLAGS, &req);
    if (ret < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to ioctl ");
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
        edge_os_log_with_error(errno, "sysioctl: failed to ioctl ");
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
        edge_os_error("sysioctl: invalid ifname ptr %p @ %s %u\n",
                            ifname, __func__, __LINE__);
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to socket ");
        return -1;
    }

    struct ifreq req;

    strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFMTU, &req);
    if (ret < 0) {
        edge_os_log_with_error(errno, "sysioctl: failed to ioctl ");
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

