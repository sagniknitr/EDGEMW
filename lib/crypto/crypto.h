#ifndef __EDGEOS_CRYPTO_H__
#define __EDGEOS_CRYPTO_H__

int edge_os_crypto_md5sum(const unsigned char *data, int datalen, uint8_t *md5sum);

int edge_os_crypto_sha1sum(const unsigned char *data, int datalen, uint8_t *sha1sum);

int edge_os_crypto_shasum(const unsigned char *data, int datalen, uint8_t *shasum);

int edge_os_crypto_sha224(const unsigned char *data, int datalen, uint8_t *sha224);

int edge_os_crypto_sha256(const unsigned char *data, int datalen, uint8_t *sha256);

int edge_os_crypto_sha384(const unsigned char *data, int datalen, uint8_t *sha384);

int edge_os_crypto_sha512(const unsigned char *data, int datalen, uint8_t *sha512);

int edge_os_crypto_gen_keyiv(uint8_t *key, int keysize, uint8_t *iv, int ivsize);

int edge_os_crypto_gen_keyiv_file(const char *keyfile, int keysize, const char *ivfile, int ivsize);

int edge_os_crypto_aes_128_cbc_encrypt(void *plain, int plainlen, void *cipher, uint8_t *key, uint8_t *iv);

int edge_os_crypto_aes_128_cbc_encrypt_file(const char *input_file, const char *output_file,
                                 const char *keyfile, const char *ivfile);

int edge_os_crypto_aes_128_cbc_decrypt(void *cipher, int cipherlen, void *plain, uint8_t *key, uint8_t *iv);

int edge_os_crypto_aes_128_cbc_decrypt_file(const char *cypher_file, const char *output_file,
                                     const char *keyfile, const char *ivfile);

#endif

