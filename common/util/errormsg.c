#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <error_codes.h>
#include <errormsg.h>
#include <errno.h>

static struct edgeos_errmsgs {
    int err;
    char *msg;
} errmsg_list[] = {
    {EDGEOS_SUCCESS, "Success (No error)"},
    {EDGEOS_ESOCK_OPEN_FAIL, "Socket open failure"},
    {EDGEOS_EBIND_FAILURE, "Bind failure"},
    {EDGEOS_EACCEPT_FAILURE, "Accept failure"},
};

void edgeos_describe_failure(int err, char *errmsg, size_t errmsg_len)
{
    uint32_t i;

    for (i = 0; i < sizeof(errmsg_list) / sizeof(errmsg_list[0]); i ++) {
        if (errmsg_list[i].err == err) {
            if ((strlen(errmsg_list[i].msg) + 1) < errmsg_len) {
                strcpy(errmsg, errmsg_list[i].msg);
                break;
            }
        }
    }
}

