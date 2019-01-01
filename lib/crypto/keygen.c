#include <stdio.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

int edge_os_crypto_key_create(uint8_t *key, int keysize)
{
    int ret;
    int size = keysize;

    RNG rng;
    byte *tmp_ = NULL;

    tmp_ = calloc(1, size);
    if (!tmp_) {
        goto bad;
    }

    ret = wc_InitRng(&rng);
    if (ret < 0) {
        goto bad;
    }

    ret = wc_RNG_GenerateBlock(&rng, key, size);
    if (ret < 0)
        goto bad;

    ret = wc_RNG_GenerateBlock(&rng, tmp_, size);
    if (ret < 0)
        goto bad;

    ret = wc_PBKDF2(key, tmp_, size, NULL, 0, 4096, size, SHA256);
    if (ret < 0)
        goto bad;

    free(tmp_);

    return 0;

bad:
    if (tmp_)
        free(tmp_);

    return -1;
}

int edge_os_crypto_key_gen(char *filename, int keysize)
{
    FILE *fp;
    int ret;
    int size = 0;

    if (keysize == 128) {
        size = 128 / 8;
    } else if (keysize == 192) {
        size = 192 / 8;
    } else if (keysize == 256) {
        size = 256 / 8;
    } else {
        return -1;
    }

    uint8_t *key;

    key = calloc(1, size);
    if (!key)
        goto bad;

    ret = edge_os_crypto_key_create(key, size);
    if (ret < 0)
        goto bad;

    fp = fopen(filename, "wb");
    if (!fp) {
        goto bad;
    }

    fwrite(key, size, 1, fp);

    fclose(fp);

    free(key);

    return 0;

bad:
    if (key)
        free(key);

    return -1;
}

