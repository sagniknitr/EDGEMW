#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef CONFIG_CRYPTO_LIB_OPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

int edge_os_md5sum(const char *data, int datalen, uint8_t *md5sum)
{
    MD5_CTX md5;
    int ret;

    ret = MD5_Init(&md5);
    if (ret < 0)
        return -1;

    ret = MD5_Update(&md5, data, datalen);
    if (ret < 0)
        return -1;

    ret = MD5_Final(md5sum, &md5);
    if (ret < 0)
        return -1;

    return 0;
}

int edge_os_md5sum_file(const char *file, uint8_t *md5sum)
{
    return -1;
}

int edge_os_sha1sum(const char *data, int datalen, uint8_t *sha1sum)
{
    return -1;
}

int edge_os_gen_keyiv(uint8_t *key, int keysize, uint8_t *iv, int ivsize)
{
    int ret;

    ret = RAND_bytes(key, keysize);
    if (ret < 0)
        return -1;

    ret = RAND_bytes(iv, ivsize);
    if (ret < 0)
        return -1;

    return 0;
}

void edge_os_hexdump(const char *str, uint8_t *buf, int buflen)
{
    int i;

    fprintf(stderr, "%s: ", str);
    for (i = 0; i < buflen; i ++)
        fprintf(stderr, "%02x", buf[i] & 0xff);
    fprintf(stderr, "\n");
}

int edge_os_aes_encrypt(void *plain, int plainlen, void *cipher, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int cipher_len;
    int ret;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (ret != 1)
        return -1;

    ret = EVP_EncryptUpdate(ctx, cipher, &len, plain, plainlen);
    if (ret != 1)
        return -1;

    cipher_len = len;

    ret = EVP_EncryptFinal_ex(ctx, cipher + len, &len);
    if (ret != 1)
        return -1;

    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return cipher_len;
}

int edge_os_aes_decrypt(void *cipher, int cipherlen, void *plain, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plain_len;
    int ret;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (ret != 1)
        return -1;

    ret = EVP_DecryptUpdate(ctx, plain, &len, cipher, cipherlen);
    if (ret != 1)
        return -1;

    plain_len = len;

    ret = EVP_DecryptFinal_ex(ctx, plain + len, &len);
    if (ret != 1)
        return -1;

    plain_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plain_len;
}



#else
int edge_os_md5sum(const char *data, int datalen, uint8_t *md5sum)
{
    return -1;
}

#endif

#if 0
int main()
{
    char msg[] = "Hello ";
    uint8_t md5sum[16];
    uint8_t key[16];
    uint8_t iv[16];
    uint32_t i;

    memset(md5sum, 0, sizeof(md5sum));

    edge_os_md5sum(msg, sizeof(msg), md5sum);
    edge_os_hexdump("md5sum", md5sum, 16);

    edge_os_gen_keyiv(key, sizeof(key), iv, sizeof(iv));

    edge_os_hexdump("key", key, sizeof(key));
    edge_os_hexdump("iv", iv, sizeof(iv));

    char cipher[120];
    int enc_len;

    char dec_out[120];
    int dec_len;

    enc_len = edge_os_aes_encrypt(msg, sizeof(msg), cipher, key, iv);

    edge_os_hexdump("aes", (uint8_t *)cipher, enc_len);

    dec_len = edge_os_aes_decrypt(cipher, enc_len, dec_out, key, iv);

    printf("plain : %s\n", dec_out);

    return 0;
}


#endif

