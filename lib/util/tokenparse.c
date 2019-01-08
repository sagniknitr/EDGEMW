#include <stdio.h>
#include <string.h>
#include <edgeos_tokparse.h>

int edge_os_token_parser(const char *input, int input_len, char token, char *op, int op_len, int off)
{
    int i = off;
    int j = 0;

    for (; i < input_len; i ++) {
        if (input[i] != token) {
            if (j < op_len)
                op[j] = input[i];
        } else {
            op[j] = '\0';
            break;
        }

        j ++;
    }

    if (off >= input_len)
        return -1;

    return i + 1;
}

#if 0
int main()
{
    char *msg = "home//devnaga//////test/work/work1/work2";
    int off = 0;
    char op[80];

    while (1) {
        off = token_parser(msg, strlen(msg), '/', op, sizeof(op), off);
        if (off == -1)
            break;
    }

    return 0;
}

#endif

