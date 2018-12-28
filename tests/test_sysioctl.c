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

    return 0;
}

