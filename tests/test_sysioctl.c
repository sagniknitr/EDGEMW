#include <stdio.h>
#include <stdint.h>
#include <sysioctl.h>

int sysioctl_test(int argc, char **argv)
{
    char ip[40];
    int ret;

    ret = edgeos_get_net_ipaddr(NULL, NULL, 0);

    ret = edgeos_get_net_ipaddr("enp67s0", ip, sizeof(ip));

    if (ret == 0)
        printf("ip %s\n", ip);

    ret = edgeos_get_net_ipaddr("wlp68s0", ip, sizeof(ip));

    if (ret == 0)
        printf("ip %s\n", ip);

    ret = edgeos_get_net_ipaddr("eth0", ip, sizeof(ip));
    if (ret == 0)
        printf("ip %s\n", ip);

    ret = edgeos_get_net_ipaddr("wlan0", ip, sizeof(ip));
    if (ret == 0)
        printf("ip %s\n", ip);

    ret = edgeos_get_net_ipaddr("lo", ip, sizeof(ip));
    if (ret == 0)
        printf("ip %s\n", ip);

    uint8_t mac[6];
    ret = edge_os_get_hwaddr("enp67s0", mac);
    if (ret == 0)
        printf("mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    ret = edge_os_get_hwaddr("wlp68s0", mac);
    if (ret == 0)
        printf("mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    ret = edge_os_get_hwaddr("wlan0", mac);
    if (ret == 0)
        printf("mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    ret = edge_os_get_hwaddr("lo", mac);
    if (ret == 0)
        printf("mac : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    ret = edge_os_get_hwaddr(NULL, NULL);

    struct edge_os_iflist *ndev, *ndev_1;

    ndev = edge_os_get_netdev_info();

    for (ndev_1 = ndev; ndev_1; ndev_1 = ndev_1->next) {
        printf("ifname: %s\n", ndev_1->ifname);

        struct edge_os_ipaddr_set *i;

        for (i = ndev_1->set; i; i = i->next) {
            printf("\tipaddr: %s\n", i->ipaddr);
        }
    }
    edge_os_free_netdev_info(ndev);

    return 0;
}

