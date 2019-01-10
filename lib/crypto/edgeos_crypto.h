#ifndef __EDGEOS_CRYPTO_H__
#define __EDGEOS_CRYPTO_H__

typedef enum {
    EDGE_OS_SECP256K1 = 1,
    EDGE_OS_SECP160k1,
    EDGE_OS_SECP160r1,
    EDGE_OS_SECP160r2,
    EDGE_OS_SECP192k1,
    EDGE_OS_SECP128r1,
    EDGE_OS_SECP128r2,
    EDGE_OS_SECP224r1,
    EDGE_OS_SECP224k1,
    EDGE_OS_BRAINPOOLP224r1,
    EDGE_OS_BRAINPOOLP256r1,
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

/**
 * Notes:
 *
 * arc4 expects the key size to be of 128 bits
 */
int edge_os_crypto_arc4_encrypt(void *plain, int plainlen, void *cipher, uint8_t *key, uint8_t *iv);

int edge_os_crypto_arc4_decrypt(void *cipher, int cipherlen, void *plain, uint8_t *key, uint8_t *iv);

int edge_os_crypto_aes_128_cbc_decrypt(void *cipher, int cipherlen, void *plain, uint8_t *key, uint8_t *iv);

int edge_os_crypto_aes_128_cbc_decrypt_file(const char *cypher_file, const char *output_file,
                                     const char *keyfile, const char *ivfile);

// signature and the length
struct edge_os_ecc_signature {
    // ECC signature
    uint8_t *signature;

    // ECC signature length
    unsigned int signature_len;
};

int edge_os_crypto_generate_keypair(const char *pubkey,
                                    edge_os_ecc_key_algorithms_t algorithm, const char *privkey);

struct edge_os_ecc_signature *
edge_os_crypto_ecc_sign_message_sha1(const unsigned char *data, int datalen,
                                     char *cert_path);

struct edge_os_ecc_signature *
edge_os_crypto_ecc_sign_message_sha256(const unsigned char *data, int datalen,
                                char *cert_path);

void edge_os_crypto_ecc_free_signature(struct edge_os_ecc_signature *sig);

/**
 * @brief - verify message with sha256
 */
int edge_os_crypto_ecc_verify_message_sha256(const uint8_t *buf, size_t bufsize,
                                             const uint8_t *signature, int signature_len, const char *pubkey);

/**
 * @brief - verify message with sha1
 */
int edge_os_crypto_ecc_verify_message_sha1(const uint8_t *buf, size_t bufsize,
                                           const uint8_t *signature, int signature_len, const char *pubkey);

/**
 * @brief - initialise crypto ops .. algorithms etc
 */
void edge_os_crypto_init(void);

/**
 * @brief - deinitialise crypto ops
 */
void edge_os_crypto_deinit(void);

void *edge_os_crypto_ssl_tcp_server_create(const char *addr, int port, int n_conn,
                                const char *certfile,  const char *privkeyfile);

void *edge_os_crypto_ssl_accept_conn(void *priv);

void *edge_os_crypto_ssl_tcp_client_create(const char *addr, const char *protocol, int port, const char *certpath, const char *keypath);

int edge_os_crypto_ssl_server_send(void *priv, void *client_priv, void *msg, int msglen);

int edge_os_crypto_ssl_server_recv(void *priv, void *client_priv, void *msg, int msglen);

int edge_os_crypto_ssl_client_send(void *priv, void *msg, int msglen);

int edge_os_crypto_ssl_client_recv(void *priv, void *msg, int msglen);

  
#endif

