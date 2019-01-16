#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <edgeos_crypto.h>
#include <edgeos_utils.h>

int crypto_test(int argc, char **argv)
{
    char msg[] = "Hello ";
    uint8_t md5sum[16];
    uint8_t sha1sum[100];
    uint8_t key[16];
    uint8_t iv[16];
    char *keyfile = "./aes_128.key";
    char *ivfile = "./aes_128.iv";
    char *input_file = "./build/libEdgeOS.a";
    char *output_file = "./build/libEdgeOS.a.enc";
    char *dec_file = "./build/libEdgeOS.a.dec";
    char *pubkey = "./secp256k1_pub.key";
    char *privkey = "./secp256k1_priv.key";
    uint8_t chacha20_key[32];
    uint8_t chacha20_iv[12];

    memset(md5sum, 0, sizeof(md5sum));

    edge_os_crypto_init();

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
    }

    ret = edge_os_crypto_aes_128_cbc_decrypt_file(output_file, dec_file,
                                    keyfile, ivfile);
    if (ret < 0) {
        fprintf(stderr, "failed to decrypt file\n");
    }

    ret = edge_os_crypto_md5sum_file((const char *)input_file, md5sum);
    edge_os_hexdump("md5sum", md5sum, 16);

    ret = edge_os_crypto_generate_keypair(pubkey, EDGE_OS_SECP256K1, privkey);
    if (ret < 0) {
        fprintf(stderr, "failed to generate keypair\n");
        return -1;
    }

    const char message[] = "message";
    struct edge_os_ecc_signature *signature;

    signature = edge_os_crypto_ecc_sign_message_sha256((const unsigned char *)message, strlen(message), privkey);
    if (!signature) {
        fprintf(stderr, "failed to sign messge\n");
    } else {
        edge_os_hexdump("signature", signature->signature, signature->signature_len);

        ret = edge_os_crypto_ecc_verify_message_sha256((const unsigned char *)message, strlen(message),
                                signature->signature,
                                signature->signature_len,
                                pubkey);
        if (ret < 0) {
            fprintf(stderr, "failed to verify message\n");
        } else {
            printf("verify status %d\n", ret);
        }
    }

    edge_os_crypto_ecc_free_signature(signature);

    edge_os_crypto_gen_keyiv(chacha20_key, sizeof(chacha20_key), chacha20_iv, sizeof(chacha20_iv));

    edge_os_hexdump("chacha20_key", chacha20_key, sizeof(chacha20_key));
    edge_os_hexdump("chacha20_iv", chacha20_iv, sizeof(chacha20_iv));

    ret = edge_os_crypto_arc4_encrypt(msg, sizeof(msg), cipher, key, iv);
    if (ret < 0) {
        fprintf(stderr, "failed to arc4 encrypt\n");
    } else {
        char arc4_dec[100];

        edge_os_hexdump("arc4_enc", (uint8_t *)cipher, ret);

        ret = edge_os_crypto_arc4_decrypt(cipher, ret, arc4_dec, key, iv);
        if (ret < 0) {
            fprintf(stderr, "failed to arc4 decrypt\n");
        } else {
            fprintf(stderr, "arc4_dec: %s", arc4_dec);
        }
    }

    uint8_t gcm_key[16];
    uint8_t gcm_iv[12];
    char plain_text_gcm[] = "gcm encryption with auth tag";
    char auth_header[] = "header info";
    uint8_t cipher_text_gcm[100];
    char plain_text_dec_g[100];
    uint8_t tag_gcm[16];

    ret = edge_os_crypto_gen_keyiv(gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv));
    if (ret != 0) {
        fprintf(stderr, "failed to generate gcm\n");
        return -1;
    }

    ret = edge_os_crypto_encrypt_aes_gcm(plain_text_gcm, strlen(plain_text_gcm), auth_header, strlen(auth_header), tag_gcm, cipher_text_gcm, gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv));
    if (ret < 0) {
        fprintf(stderr, "failed to encrypt gcm\n");
        return -1;
    }

    printf("encrypt ok\n");

    edge_os_hexdump_pretty("encrypted out", cipher_text_gcm, ret);
    edge_os_hexdump_pretty("tag", tag_gcm, 16);

    ret = edge_os_crypto_decrypt_aes_gcm(cipher_text_gcm, ret, tag_gcm, auth_header, strlen(auth_header), gcm_key, sizeof(gcm_key), gcm_iv, sizeof(gcm_iv), plain_text_dec_g);
    if (ret < 0) {
        fprintf(stderr, "failed to decrypt gcm\n");
        return -1;
    }

    printf("decrypt ok\n");

    printf("decrypt text *%s*\n", plain_text_dec_g);

    edge_os_crypto_deinit();

    return 0;
}

