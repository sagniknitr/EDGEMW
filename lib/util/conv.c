#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <edgeos_logger.h>

int edge_os_stoi(const char *str, int *val, int base_10)
{
    char *err = NULL;
    int base = 16;

    if (!val) {
        edge_os_error("conv: invalid val @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    if (base_10)
        base = 10;


    *val = strtol(str, &err, base);
    if (err && (err[0] != '\0')) {
        edge_os_error("conv: invalid input string <%s> error at <%s> \n",
                            str, err);
        return -1;
    }

    return 0;
}

int edge_os_stou(const char *str, uint32_t *val, int base_10)
{
    char *err = NULL;
    int base = 16;

    if (!val) {
        edge_os_error("conv: invalid val @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    if (base_10)
        base = 10;


    *val = strtoul(str, &err, base);
    if (err && (err[0] != '\0')) {
        edge_os_error("conv: invalid input string <%s> error at <%s> \n",
                            str, err);
        return -1;
    }

    return 0;
}

int edge_os_stod(const char *str, double *val)
{
    char *err = NULL;

    if (!val) {
        edge_os_error("conv: invalid val @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    *val = strtod(str, &err);
    if (err && (err[0] != '\0')) {
        edge_os_error("conv: invalid input string <%s> error at <%s> \n",
                            str, err);
        return -1;
    }

    return 0;

}

int edge_os_stoul(const char *str, unsigned long *val, int base_10)
{
    char *err = NULL;
    int base = 16;

    if (!val) {
        edge_os_error("conv: invalid val @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    if (base_10)
        base = 10;


    *val = strtoul(str, &err, base);
    if (err && (err[0] != '\0')) {
        edge_os_error("conv: invalid input string <%s> error at <%s> \n",
                            str, err);
        return -1;
    }

    return 0;
}

int edge_os_stoull(const char *str, unsigned long long *val, int base_10)
{
    char *err = NULL;
    int base = 16;

    if (!val) {
        edge_os_error("conv: invalid val @ %s %u\n",
                            __func__, __LINE__);
        return -1;
    }

    if (base_10)
        base = 10;


    *val = strtoull(str, &err, base);
    if (err && (err[0] != '\0')) {
        edge_os_error("conv: invalid input string <%s> error at <%s> \n",
                            str, err);
        return -1;
    }

    return 0;
}

int edge_os_itos(int val, char *str, int len, int base_10)
{
    char hex[10] = "%x";

    if (!str || (len <= 0)) {
        edge_os_error("conv: invalid str @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    if (base_10)
        strcpy(hex, "%d");

    snprintf(str, len, hex, val);

    return 0;
}

int edge_os_itou(uint32_t val, char *str, int len, int base_10)
{
    char hex[10] = "%x";

    if (!str || (len <= 0)) {
        edge_os_error("conv: invalid str @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    if (base_10)
        strcpy(hex, "%u");

    snprintf(str, len, hex, val);

    return 0;
}

int edge_os_dtos(double val, char *str, int len)
{
    if (!str || (len <= 0)) {
        edge_os_error("conv: invalid str @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    snprintf(str, len, "%f", val);

    return 0;
}

int edge_os_ultos(unsigned long val, char *str, int len, int base_10)
{
    char hex[10] = "%x";

    if (!str || (len <= 0)) {
        edge_os_error("conv: invalid str @ %s %u\n",
                                __func__, __LINE__);
        return -1;
    }

    if (base_10)
        strcpy(hex, "%lu");

    snprintf(str, len, hex, val);

    return 0;
}

