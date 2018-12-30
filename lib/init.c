#include <stdio.h>
#include <stdlib.h>
#include <eos_init.h>
#include <edgeos_logger.h>

struct edge_os_lib_priv {
    void *log_priv;
};

void* edgeos_init_lib(struct edge_os_config *config)
{
    struct edge_os_lib_priv *priv;

    priv = calloc(1, sizeof(struct edge_os_lib_priv));
    if (!priv) {
        return NULL;
    }

    priv->log_priv = edge_os_logger_init(config->logger_config.logger_ip,
                                         config->logger_config.logger_port);
    if (!priv->log_priv) {
        goto err;
    }

    edge_os_set_logger_fallback_local(priv->log_priv);

    return priv;

err:
    free(priv);
    return NULL;
}

void edgeos_log_info(void *handle, char *fmt, ...)
{
    struct edge_os_lib_priv *priv = handle;
    va_list ap;

    va_start(ap, fmt);

    edge_os_logger_write_valist(priv->log_priv, "info: ", ap);

    va_end(ap);
}

void edgeos_log_warn(void *handle, char *fmt, ...)
{
    struct edge_os_lib_priv *priv = handle;
    va_list ap;

    va_start(ap, fmt);

    edge_os_logger_write_valist(priv->log_priv, "warn: ", ap);

    va_end(ap);
}

void edge_os_log_err(void *handle, char *fmt, ...)
{
    struct edge_os_lib_priv *priv = handle;
    va_list ap;

    va_start(ap, fmt);

    edge_os_logger_write_valist(priv->log_priv, "error: ", ap);

    va_end(ap);
}

