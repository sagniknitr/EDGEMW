#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <crypto.h>
#include <utils.h>

int crypto_test(int argc, char **argv)
{
    char msg[] = "Hello ";
    uint8_t md5sum[16];
    uint8_t sha1sum[100];
    uint8_t key[16];
    uint8_t iv[16];
    char *keyfile = "./aes_128.key";
    char *ivfile = "./aes_128.iv";
    char *input_file = "./libEdgeOS.a";
    char *output_file = "./libEdgeOS.a.enc";
    char *dec_file = "./libEdgeOS.a.dec";

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

    enc_len = edge_os_crypto_aes_128_cbc_encrypt(msg, sizeof(msg), cipher, key, iv);

    edge_os_hexdump("aes", (uint8_t *)cipher, enc_len);

    edge_os_crypto_aes_128_cbc_decrypt(cipher, enc_len, dec_out, key, iv);

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

    ret = edge_os_crypto_md5sum_file((const char *)input_file, md5sum);
    edge_os_hexdump("md5sum", md5sum, 16);

    return 0;
}

