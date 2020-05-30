#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <edgeos_crypto.h>

int ssl_test(int argc, char **argv)
{
    void *priv;

    if (!strcmp(argv[1], "server")) {
        priv = edge_os_crypto_ssl_tcp_server_create(
                            "127.0.0.1",
                            4141,
                            10,
                            "sagniknitr.crt",
                            "sagniknitr_priv.key");
        if (!priv) {
            return -1;
        }

        void *client_handle;

        client_handle = edge_os_crypto_ssl_accept_conn(priv);

        char *msg= "server says --";
        edge_os_crypto_ssl_server_send(priv, client_handle, msg, strlen(msg));

    } else {
        priv = edge_os_crypto_ssl_tcp_client_create(
                            "127.0.0.1",
                            NULL,
                            4141,
                            NULL,
                            NULL);
        if (priv) {
            printf("client connection %p\n", priv);
            char msg[100];

            edge_os_crypto_ssl_client_recv(priv, msg, sizeof(msg));
            printf("server msg: %s\n", msg);
        }

        priv = edge_os_crypto_ssl_tcp_client_create(
                            "www.google.com",
                            "https",
                            4141,
                            NULL,
                            NULL);
        printf("google : %p\n", priv);
    }

    return 0;
}


