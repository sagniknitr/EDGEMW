#include <stdio.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

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

    RNG rng;
    byte *key = NULL;
    byte *tmp_ = NULL;
    byte *salt = NULL;

    key = calloc(1, size);
    if (!key) {
        goto bad;
    }

    tmp_ = calloc(1, size);
    if (!tmp_) {
        goto bad;
    }

    salt = calloc(1, size);
    if (!salt) {
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

    ret = wc_RNG_GenerateBlock(&rng, salt, size);
    if (ret < 0)
        goto bad;

    ret = wc_PBKDF2(key, tmp_, size, salt, size, 4096, size, SHA256);
    if (ret < 0)
        goto bad;

    fp = fopen(filename, "wb");
    if (!fp) {
        goto bad;
    }

    fwrite(key, size, 1, fp);

    fclose(fp);

    free(key);
    free(tmp_);
    free(salt);

    return 0;

bad:
    if (key)
        free(key);

    if (tmp_)
        free(tmp_);

    if (salt)
        free(salt);

    return -1;
}

