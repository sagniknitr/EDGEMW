#ifndef __EDGEOS_SYSIOCTL_H__
#define __EDGEOS_SYSIOCTL_H__

int edgeos_get_net_ipaddr(const char *ifname, char *ip, int iplen);

int edge_os_get_hwaddr(const char *ifname, uint8_t *macaddr);

struct edge_os_ipaddr_set {
    int is_ipv6addr;
    char ipaddr[120];
    char netmask[120];
    char broad_addr[120];
    struct edge_os_ipaddr_set *next;
};

struct edge_os_iflist {
    char ifname[20];
    int has_broadcast_set;
    int has_mcast_set;
    int if_up;
    int is_loopback;
    int ipaddr_count;
    struct edge_os_ipaddr_set *set;
    struct edge_os_iflist *next;
};


struct edge_os_iflist* edge_os_get_netdev_info();
void edge_os_free_netdev_info(struct edge_os_iflist *dev);

#endif

