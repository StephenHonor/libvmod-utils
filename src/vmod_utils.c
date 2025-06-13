#define _GNU_SOURCE

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "cache/cache.h"
#include "vcc_utils_if.h"

struct vmod_utils_data {
    char* hostname;
};

void utils_free(void* priv)
{
    struct vmod_utils_data* data = (struct vmod_utils_data*)priv;

#define freez(x) do { if (x) free(x); x = NULL; } while (0);
    freez(data->hostname);
    freez(data);
#undef freez
}

static const struct vmod_priv_methods priv_task_methods[1] = {{
    .magic = VMOD_PRIV_METHODS_MAGIC,
    .type = "vmod_utils_priv_task",
    .fini = utils_free
}};

void* utils_init(void)
{
    struct vmod_utils_data* data = malloc(sizeof(struct vmod_utils_data));
    AN(data);

    data->hostname = malloc(HOST_NAME_MAX + 1);
    AN(data->hostname);

    if(gethostname(data->hostname, HOST_NAME_MAX) == -1) {
        syslog(LOG_ERR, "gethostname failed: %s", strerror(errno));
        strcpy(data->hostname, "<unknown>");
    }
    return (void*)data;
}

int
event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{
    switch (e) {
        case VCL_EVENT_LOAD:
            if (priv->priv == NULL) {
                priv->priv = utils_init();
                priv->methods = priv_task_methods;
            }
            break;
        default:
            break;
    }
    return (0);
}

double
vmod_real(VRT_CTX, VCL_STRING p, VCL_REAL d)
{
    char *e;
    double r;

    if (p == NULL)
        return (d);

    e = NULL;
    r = strtod(p, &e);

    if (e == NULL)
        return (d);
    if (*e != '\0')
        return (d);
    return (r);
}

VCL_STRING
vmod_hostname(VRT_CTX, struct vmod_priv *priv)
{
    struct vmod_utils_data* data = (struct vmod_utils_data*)priv->priv;
    return data->hostname;
}

VCL_STRING
vmod_timestamp(VRT_CTX)
{
    char *p;
    #define TIMESTAMP_LENGTH 64
    p = WS_Alloc(ctx->ws, TIMESTAMP_LENGTH);
    if (p == NULL) {
        return "WS_Alloc_error";
    }
    snprintf(p, TIMESTAMP_LENGTH, "%.9f", VTIM_real());
    return p;
}

VCL_BOOL
vmod_exists(VRT_CTX, VCL_STRING path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

VCL_BLOB
vmod_ip(VRT_CTX, VCL_STRING s, VCL_BLOB d)
{
    struct addrinfo hints, *res0 = NULL;
    const struct addrinfo *res;
    int error;
    void *p;
    struct sockaddr_storage *r = NULL;
    static int l = sizeof(struct sockaddr_storage);

    p = WS_Alloc(ctx->ws, l);
    if (p == NULL) {
        syslog(LOG_ERR, "vmod std.ip(): insufficient workspace");
        return d;
    }

    if (s != NULL) {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        error = getaddrinfo(s, "80", &hints, &res0);
        if (!error) {
            for (res = res0; res != NULL; res = res->ai_next) {
                r = p;
                memcpy(r, res->ai_addr, res->ai_addrlen);
                break;
            }
        }
    }
    if (r == NULL) {
        r = p;
        memcpy(r, d->blob, l);
    }
    if (res0 != NULL)
        freeaddrinfo(res0);

    return VRT_blob(ctx, "ip", r, l, NULL);
}
