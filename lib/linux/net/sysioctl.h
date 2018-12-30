#ifndef __EDGEOS_SYSIOCTL_H__
#define __EDGEOS_SYSIOCTL_H__

int edgeos_get_net_ipaddr(const char *ifname, char *ip, int iplen);

int edge_os_get_hwaddr(const char *ifname, uint8_t *macaddr);

#endif

