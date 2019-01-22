/**
 * @brief - generic Linux IOCTL call support header (possibly more other ioctl calls as well)
 *
 * @Author - Devendra Naga (devendra.aaru@gmail.com)
 * @Copyright - All rights reserved
 *
 * MIT License
 */

#ifndef __EDGEOS_SYSIOCTL_H__
#define __EDGEOS_SYSIOCTL_H__

/**
 * @brief - ip address information set is part of the edge_os_iflist
 */
struct edge_os_ipaddr_set {
	// if the ip is an ipv6 ?
    int is_ipv6addr;
	// ip address v4 or v6
#define EDGEOS_IPADDR_IS_V4(__ipset) !!(__ipset->is_ipv6addr)
    char ipaddr[120];
	// network mask of the interface
    char netmask[120];
	// broadcast address of the interface
    char broad_addr[120];
	// next item in the list
    struct edge_os_ipaddr_set *next;
};

/**
 * @brief - set of interface list populated by edge_os_get_netdev_info
 */
struct edge_os_iflist {
	// interface name
    char ifname[20];

	// set to 1 if the interface has broadcast flag set
    int has_broadcast_set;

	// set to 1 if the interface has multicast flag set
    int has_mcast_set;

	// set to 1 if the interface is up
    int if_up;

	// set to 1 if the interface is loopback
    int is_loopback;

    // set to 1 if the interface is running
    int is_running;

	// set to 1 if the interface is in promiscous mode
	int is_promisc;

	// number of ipaddress on this interface
    int ipaddr_count;

	// set of ipaddress list for this interface
    struct edge_os_ipaddr_set *set;

	// next interface set
    struct edge_os_iflist *next;
};


int edgeos_get_net_ipaddr(const char *ifname, char *ip, int iplen);

int edge_os_set_net_ipaddr(const char *ifname, const char *ip);

int edge_os_get_hwaddr(const char *ifname, uint8_t *macaddr);

int edge_os_set_hwaddr(const char *ifname, const uint8_t *macaddr);

int edge_os_is_mac_zero(const uint8_t *macaddr);

int edge_os_is_mac_broadcast(const uint8_t *macaddr);

int edge_os_is_mac_multicast(const uint8_t *macaddr);

int edge_os_is_if_lo(const char *ifname);

int edge_os_is_if_broadcast(const char *ifname);

int edge_os_is_if_multicast(const char *ifname);

int edge_os_is_if_running(const char *ifname);

int edge_os_is_if_up(const char *ifname);

int edge_os_set_loopback(const char *ifname);

int edge_os_set_broadcast(const char *ifname);

int edge_os_set_multicast(const char *ifname);

int edge_os_set_iface_up(const char *ifname);

int edge_os_get_mtu(const char *ifname);

int edge_os_get_netmask(const char *name, const char *mask);

struct edge_os_iflist* edge_os_get_netdev_info();

void edge_os_free_netdev_info(struct edge_os_iflist *dev);

int edge_os_set_iface_promisc(const char *ifname);

int edge_os_is_if_promisc(const char *ifname);

int edge_os_set_iface_remove_promisc(const char *iface);

int edge_os_set_iface_no_running(const char *ifname);

int edge_os_set_iface_running(const char *ifname);

#endif

