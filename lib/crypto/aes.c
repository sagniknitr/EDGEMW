#include <stdio.h>
#include <keygen.h>

int edge_os_aes_keygen(char *filename, int keysize)
{
    return edge_os_crypto_key_gen(filename, keysize);
}

