#ifndef __EDGEOS_CONV_H__
#define __EDGEOS_CONV_H__

int edge_os_stoi(const char *str, int *val, int base_10);

int edge_os_stou(const char *str, uint32_t *val, int base_10);

int edge_os_stod(const char *str, double *val);

int edge_os_stoul(const char *str, unsigned long *val, int base_10);

int edge_os_stoull(const char *str, unsigned long long *val, int base_10);

int edge_os_itos(int val, char *str, int len, int base_10);

int edge_os_itou(uint32_t val, char *str, int len, int base_10);

int edge_os_dtos(double val, char *str, int len);

int edge_os_ultos(unsigned long val, char *str, int len, int base_10);

#endif

