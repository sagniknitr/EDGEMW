#ifndef __EDGEOS_CRYPTO_H__
#define __EDGEOS_CRYPTO_H__

typedef enum {
    EDGE_OS_SECP256K1 = 1,
    EDGE_OS_SECP128r1 = 2,
    EDGE_OS_SECP128r2 = 3,
    EDGE_OS_SECP224r1 = 4,
    EDGE_OS_BRAINPOOLP224r1 = 5,
    EDGE_OS_BRAINPOOLP256r1 = 6,
} edge_os_ecc_key_algorithms_t;



int edge_os_crypto_md5sum(const unsigned char *data, int datalen, uint8_t *md5sum);

int edge_os_crypto_md5sum_file(const char *file, uint8_t *md5sum);

int edge_os_crypto_sha1sum(const unsigned char *data, int datalen, uint8_t *sha1sum);

int edge_os_crypto_sha1sum_file(const char *file, uint8_t *sha1sum);

int edge_os_crypto_shasum(const unsigned char *data, int datalen, uint8_t *shasum);

int edge_os_crypto_shasum_file(const char *file, uint8_t *shasum);

int edge_os_crypto_sha224(const unsigned char *data, int datalen, uint8_t *sha224);

int edge_os_crypto_sha224_file(const char *file, uint8_t *sha224);

int edge_os_crypto_sha256(const unsigned char *data, int datalen, uint8_t *sha256);

int edge_os_crypto_sha256_file(const char *file, uint8_t *sha256);

int edge_os_crypto_sha384(const unsigned char *data, int datalen, uint8_t *sha384);

int edge_os_crypto_sha384_file(const char *file, uint8_t *sha384);

int edge_os_crypto_sha512(const unsigned char *data, int datalen, uint8_t *sha512);

int edge_os_crypto_sha512_file(const char *file, uint8_t *sha512);

int edge_os_crypto_gen_keyiv(uint8_t *key, int keysize, uint8_t *iv, int ivsize);

int edge_os_crypto_gen_keyiv_file(const char *keyfile, int keysize, const char *ivfile, int ivsize);

int edge_os_crypto_load_pem_ec(const char *pkey_file, const char *pubkey_file);

int generate_keypair(const char *pubkey, const char *privkey);

int edge_os_crypto_aes_128_cbc_encrypt(void *plain, int plainlen, void *cipher, uint8_t *key, uint8_t *iv);

int edge_os_crypto_aes_128_cbc_encrypt_file(const char *input_file, const char *output_file,
                                 const char *keyfile, const char *ivfile);

int edge_os_crypto_aes_128_cbc_decrypt(void *cipher, int cipherlen, void *plain, uint8_t *key, uint8_t *iv);

int edge_os_crypto_aes_128_cbc_decrypt_file(const char *cypher_file, const char *output_file,
                                     const char *keyfile, const char *ivfile);

struct edge_os_ecc_signature {
    uint8_t *signature;
    unsigned int signature_len;
};

int edge_os_crypto_generate_keypair(const char *pubkey, edge_os_ecc_key_algorithms_t algorithm, const char *privkey);

struct edge_os_ecc_signature *
edge_os_crypto_ecc_sign_message_sha1(const unsigned char *data, int datalen,
                                     char *cert_path);

struct edge_os_ecc_signature *
edge_os_crypto_ecc_sign_message_sha256(const unsigned char *data, int datalen,
                                char *cert_path);

void edge_os_crypto_ecc_free_signature(struct edge_os_ecc_signature *sig);

int edge_os_crypto_ecc_verify_message_sha256(const uint8_t *buf, size_t bufsize, const uint8_t *signature, int signature_len, const char *pubkey);

int edge_os_crypto_ecc_verify_message_sha1(const uint8_t *buf, size_t bufsize, const uint8_t *signature, int signature_len, const char *pubkey);

void edge_os_crypto_init(void);

void edge_os_crypto_deinit(void);

#endif

