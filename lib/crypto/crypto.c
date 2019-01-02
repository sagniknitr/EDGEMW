#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fsapi.h>

#ifdef CONFIG_CRYPTO_LIB_OPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

typedef enum {
    EDGE_OS_CRYPTO_MD5,
    EDGE_OS_CRYPTO_SHA,
    EDGE_OS_CRYPTO_SHA1,
    EDGE_OS_CRYPTO_SHA224,
    EDGE_OS_CRYPTO_SHA256,
    EDGE_OS_CRYPTO_SHA384,
    EDGE_OS_CRYPTO_SHA512,
} edge_os_crypto_digest_t;

int __edge_os_crypto_digest_msg(const unsigned char *msg, edge_os_crypto_digest_t digest, size_t msglen, uint8_t *digest_final)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md = NULL;
    int digest_len;
    int ret;

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return -1;

    switch (digest) {
        case EDGE_OS_CRYPTO_MD5:
            md = EVP_md5();
        break;
        case EDGE_OS_CRYPTO_SHA:
            md = EVP_sha();
        break;
        case EDGE_OS_CRYPTO_SHA1:
            md = EVP_sha1();
        break;
        case EDGE_OS_CRYPTO_SHA224:
            md = EVP_sha224();
        break;
        case EDGE_OS_CRYPTO_SHA256:
            md = EVP_sha256();
        break;
        case EDGE_OS_CRYPTO_SHA384:
            md = EVP_sha384();
        break;
        case EDGE_OS_CRYPTO_SHA512:
            md = EVP_sha512();
        break;
        default:
            return -1;
    }

    ret = EVP_DigestInit(ctx, md);
    if (ret != 1)
        goto bad;

    ret = EVP_DigestUpdate(ctx, msg, msglen);
    if (ret != 1)
        goto bad;

    ret = EVP_DigestFinal_ex(ctx, digest_final, (unsigned int *)&digest_len);
    if (ret != 1)
        goto bad;

    EVP_MD_CTX_destroy(ctx);

    return digest_len;

bad:
    return -1;
}

int __edge_os_crypto_digest_file(const char *file, edge_os_crypto_digest_t digest, uint8_t *digest_final)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md = NULL;
    int digest_len;
    int fd = -1;
    int ret;

    ctx = EVP_MD_CTX_create();
    if (!ctx)
        return -1;

    switch (digest) {
        case EDGE_OS_CRYPTO_MD5:
            md = EVP_md5();
        break;
        case EDGE_OS_CRYPTO_SHA:
            md = EVP_sha();
        break;
        case EDGE_OS_CRYPTO_SHA1:
            md = EVP_sha1();
        break;
        case EDGE_OS_CRYPTO_SHA224:
            md = EVP_sha224();
        break;
        case EDGE_OS_CRYPTO_SHA256:
            md = EVP_sha256();
        break;
        case EDGE_OS_CRYPTO_SHA384:
            md = EVP_sha384();
        break;
        case EDGE_OS_CRYPTO_SHA512:
            md = EVP_sha512();
        break;
        default:
            return -1;
    }

    ret = EVP_DigestInit(ctx, md);
    if (ret != 1)
        goto bad;

    fd = edgeos_open_file(file, "r");
    if (fd < 0)
        goto bad;

    uint8_t input[1024];

    while (1) {
        ret = edgeos_read_file(fd, input, sizeof(input));
        if (ret <= 0)
            break;

        ret = EVP_DigestUpdate(ctx, input, ret);
        if (ret != 1)
            goto bad;
    }

    edgeos_close_file(fd);

    ret = EVP_DigestFinal_ex(ctx, digest_final, (unsigned int *)&digest_len);
    if (ret != 1)
        goto bad;

    EVP_MD_CTX_destroy(ctx);

    return digest_len;

bad:
    EVP_MD_CTX_destroy(ctx);
    if (fd > 0)
        edgeos_close_file(fd);

    return -1;
}


int edge_os_crypto_md5sum(const unsigned char *data, int datalen, uint8_t *md5sum)
{
    return __edge_os_crypto_digest_msg(data, EDGE_OS_CRYPTO_MD5, datalen, md5sum);
}

int edge_os_crypto_md5sum_file(const char *file, uint8_t *md5sum)
{
    return __edge_os_crypto_digest_file(file, EDGE_OS_CRYPTO_MD5, md5sum);
}

int edge_os_crypto_sha1sum(const unsigned char *data, int datalen, uint8_t *sha1sum)
{
    return __edge_os_crypto_digest_msg(data, EDGE_OS_CRYPTO_SHA1, datalen, sha1sum);
}

int edge_os_crypto_sha1sum_file(const char *file, uint8_t *sha1sum)
{
    return __edge_os_crypto_digest_file(file, EDGE_OS_CRYPTO_SHA1, sha1sum);
}

int edge_os_crypto_shasum(const unsigned char *data, int datalen, uint8_t *shasum)
{
    return __edge_os_crypto_digest_msg(data, EDGE_OS_CRYPTO_SHA, datalen, shasum);
}

int edge_os_crypto_shasum_file(const char *file, uint8_t *shasum)
{
    return __edge_os_crypto_digest_file(file, EDGE_OS_CRYPTO_SHA, shasum);
}

int edge_os_crypto_sha224(const unsigned char *data, int datalen, uint8_t *sha224)
{
    return __edge_os_crypto_digest_msg(data, EDGE_OS_CRYPTO_SHA224, datalen, sha224);
}

int edge_os_crypto_sha224_file(const char *file, uint8_t *sha224)
{
    return __edge_os_crypto_digest_file(file, EDGE_OS_CRYPTO_SHA224, sha224);
}

int edge_os_crypto_sha256(const unsigned char *data, int datalen, uint8_t *sha256)
{
    return __edge_os_crypto_digest_msg(data, EDGE_OS_CRYPTO_SHA256, datalen, sha256);
}

int EDGE_OS_CRYPTO_SHA256_file(const char *file, uint8_t *sha256)
{
    return __edge_os_crypto_digest_file(file, EDGE_OS_CRYPTO_SHA256, sha256);
}

int edge_os_crypto_sha384(const unsigned char *data, int datalen, uint8_t *sha384)
{
    return __edge_os_crypto_digest_msg(data, EDGE_OS_CRYPTO_SHA384, datalen, sha384);
}

int edge_os_crypto_sha384_file(const char *file, uint8_t *sha384)
{
    return __edge_os_crypto_digest_file(file, EDGE_OS_CRYPTO_SHA384, sha384);
}

int edge_os_crypto_sha512(const unsigned char *data, int datalen, uint8_t *sha512)
{
    return __edge_os_crypto_digest_msg(data, EDGE_OS_CRYPTO_SHA512, datalen, sha512);
}

int edge_os_crypto_sha512_file(const char *file, uint8_t *sha512)
{
    return __edge_os_crypto_digest_file(file, EDGE_OS_CRYPTO_SHA512, sha512);
}

int edge_os_crypto_gen_keyiv(uint8_t *key, int keysize, uint8_t *iv, int ivsize)
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

int edge_os_crypto_gen_keyiv_file(const char *keyfile, int keysize, const char *ivfile, int ivsize)
{
    int ret;
    uint8_t *key = NULL;
    uint8_t *iv = NULL;

    key = calloc(1, keysize / 8);
    if (!key)
        return -1;

    iv = calloc(1, ivsize / 8);
    if (!iv)
        goto bad;

    ret = edge_os_crypto_gen_keyiv(key, keysize / 8, iv, ivsize / 8);
    if (ret < 0)
        goto bad;

    edge_os_write_file2(keyfile, key, keysize / 8);
    edge_os_write_file2(ivfile, iv, ivsize / 8);

    free(key);
    free(iv);

    return 0;

bad:
    if (key)
        free(key);

    if (iv)
        free(iv);

    return -1;
}

void edge_os_hexdump(const char *str, uint8_t *buf, int buflen)
{
    int i;

    fprintf(stderr, "%s: ", str);
    for (i = 0; i < buflen; i ++)
        fprintf(stderr, "%02x", buf[i] & 0xff);
    fprintf(stderr, "\n");
}

enum {
    EDGEOS_CIPHER_AES_128_CBC,
    EDGEOS_CIPHER_AES_256_CBC,
};

int __edge_os_crypto_encrypt(void *plain, int plainlen, int cipher_type, void *cipher, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int cipher_len;
    int ret;
    const EVP_CIPHER *crypto_cipher;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    switch (cipher_type) {
        case EDGEOS_CIPHER_AES_128_CBC:
            crypto_cipher = EVP_aes_128_cbc();
        break;
        case EDGEOS_CIPHER_AES_256_CBC:
            crypto_cipher = EVP_aes_256_cbc();
        break;
        default:
            return -1;
    }

    ret = EVP_EncryptInit_ex(ctx, crypto_cipher, NULL, key, iv);
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


int edge_os_crypto_aes_128_cbc_encrypt(void *plain, int plainlen, void *cipher, uint8_t *key, uint8_t *iv)
{
    return __edge_os_crypto_encrypt(plain, plainlen, EDGEOS_CIPHER_AES_128_CBC, cipher, key, iv);
}

// small files - keys
static int edge_os_parse_binary_file(const char *file, uint8_t *buf, int bufsize)
{
    int fd;
    int ret = -1;

    fd = edgeos_open_file(file, "r");
    if (fd < 0)
        return -1;

    ret = edgeos_read_file(fd, buf, bufsize);
    if (ret > 0) {
        ret = 0;
    } else {
        ret = -1;
    }

    edgeos_close_file(fd);

    return ret;
}

int __edge_os_crypto_encrypt_file(const char *input_file, const char *output_file, int cipher_type,
                                 const char *keyfile, const char *ivfile)
{
    uint8_t key[16];
    uint8_t iv[16];
    int fd_in = -1;
    int fd_out = -1;
    int len;
    int ret;

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    ret = edge_os_parse_binary_file(keyfile, key, sizeof(key));
    if (ret < 0)
        goto bad;

    ret = edge_os_parse_binary_file(ivfile, iv, sizeof(iv));
    if (ret < 0)
        goto bad;

    fd_in = edgeos_open_file(input_file, "r");
    if (fd_in < 0)
        goto bad;

    fd_out = edgeos_open_file(output_file, "w");
    if (fd_out < 0)
        goto bad;

    uint8_t plain[1024];
    uint8_t cipher[2048];
    int cipher_len;

    while (1) {
        len = edgeos_read_file(fd_in, plain, sizeof(plain));
        if (len <= 0)
            break;

        cipher_len = __edge_os_crypto_encrypt(plain, len, cipher_type, cipher, key, iv);
        if (cipher_len < 0)
            goto bad;

        edgeos_write_file(fd_out, cipher, cipher_len);
    }

    close(fd_in);
    close(fd_out);

    return 0;

bad:
    if (fd_in > 0)
        close(fd_in);

    if (fd_out > 0)
        close(fd_out);

    return -1;
}


int edge_os_crypto_aes_128_cbc_encrypt_file(const char *input_file, const char *output_file,
                                 const char *keyfile, const char *ivfile)
{
    return __edge_os_crypto_encrypt_file(input_file, output_file, EDGEOS_CIPHER_AES_128_CBC, keyfile, ivfile);
}

int __edge_os_crypto_decrypt(void *cipher, int cipherlen, int cipher_type, void *plain, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *crypto_cipher;
    int len;
    int plain_len;
    int ret;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    switch (cipher_type) {
        case EDGEOS_CIPHER_AES_128_CBC:
            crypto_cipher = EVP_aes_128_cbc();
        break;
        case EDGEOS_CIPHER_AES_256_CBC:
            crypto_cipher = EVP_aes_256_cbc();
        break;
        default:
            return -1;
    }

    ret = EVP_DecryptInit_ex(ctx, crypto_cipher, NULL, key, iv);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    ret = EVP_DecryptUpdate(ctx, plain, &len, cipher, cipherlen);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    plain_len = len;

    ret = EVP_DecryptFinal_ex(ctx, plain + len, &len);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    plain_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plain_len;
}


int edge_os_crypto_aes_128_cbc_decrypt(void *cipher, int cipherlen, void *plain, uint8_t *key, uint8_t *iv)
{
    return __edge_os_crypto_decrypt(cipher, cipherlen, EDGEOS_CIPHER_AES_128_CBC, plain, key, iv);
}

int __edge_os_crypto_decrypt_file(const char *cypher_file, const char *output_file, int cipher_type,
                                     const char *keyfile, const char *ivfile)
{
    uint8_t key[16];
    uint8_t iv[16];
    int fd_in = -1;
    int fd_out = -1;
    int len;
    int ret;

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    ret = edge_os_parse_binary_file(keyfile, key, sizeof(key));
    if (ret < 0)
        goto bad;

    ret = edge_os_parse_binary_file(ivfile, iv, sizeof(iv));
    if (ret < 0)
        goto bad;

    fd_in = edgeos_open_file(cypher_file, "r");
    if (fd_in < 0)
        goto bad;

    fd_out = edgeos_open_file(output_file, "w");
    if (fd_out < 0)
        goto bad;

    uint8_t plain[2048];
    uint8_t cipher[1040];
    int plain_len;

    while (1) {
        len = edgeos_read_file(fd_in, cipher, sizeof(cipher));
        if (len <= 0)
            break;

        plain_len = __edge_os_crypto_decrypt(cipher, len, cipher_type, plain, key, iv);
        if (plain_len < 0)
            goto bad;

        edgeos_write_file(fd_out, plain, plain_len);
    }

    close(fd_in);
    close(fd_out);

    return 0;

bad:
    if (fd_in > 0)
        close(fd_in);

    if (fd_out > 0)
        close(fd_out);

    return -1;

}


int edge_os_crypto_aes_128_cbc_decrypt_file(const char *cypher_file, const char *output_file,
                                     const char *keyfile, const char *ivfile)
{
    return __edge_os_crypto_decrypt_file(cypher_file, output_file, EDGEOS_CIPHER_AES_128_CBC, keyfile, ivfile);
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
    uint8_t sha1sum[100];
    uint8_t key[16];
    uint8_t iv[16];
    char *keyfile = "./aes_128.key";
    char *ivfile = "./aes_128.iv";
    char *input_file = "./lib/crypto/crypto.c";
    char *output_file = "./crypto.c.enc";
    char *dec_file = "./crypt.c.dec";
    uint32_t i;

    memset(md5sum, 0, sizeof(md5sum));

    edge_os_crypto_md5sum((const unsigned char *)msg, strlen(msg), md5sum);
    edge_os_hexdump("md5sum", md5sum, 16);

    memset(sha1sum, 0, sizeof(sha1sum));
    edge_os_crypto_sha1sum((const unsigned char *)msg, strlen(msg), sha1sum);
    edge_os_hexdump("sha1sum", sha1sum, 20);

    edge_os_crypto_gen_keyiv(key, sizeof(key), iv, sizeof(iv));

    edge_os_hexdump("key", key, sizeof(key));
    edge_os_hexdump("iv", iv, sizeof(iv));

    char cipher[120];
    int enc_len;

    char dec_out[120];
    int dec_len;

    enc_len = edge_os_crypto_aes_128_cbc_encrypt(msg, sizeof(msg), cipher, key, iv);

    edge_os_hexdump("aes", (uint8_t *)cipher, enc_len);

    dec_len = edge_os_crypto_aes_128_cbc_decrypt(cipher, enc_len, dec_out, key, iv);

    printf("plain : %s\n", dec_out);

    edge_os_crypto_gen_keyiv_file(keyfile, 128, ivfile, 128);

    int ret;

    ret = edge_os_crypto_aes_128_cbc_encrypt_file(input_file, output_file,
                                    keyfile, ivfile);
    if (ret < 0) {
        fprintf(stderr, "failed to encrypt file\n");
        return -1;
    }

    ret = edge_os_crypto_aes_128_cbc_decrypt_file(output_file, dec_file,
                                    keyfile, ivfile);
    if (ret < 0) {
        fprintf(stderr, "failed to decrypt file\n");
        return -1;
    }

    ret = edge_os_crypto_md5sum_file(input_file, md5sum);
    edge_os_hexdump("md5sum", md5sum, 16);

    return 0;
}


#endif

