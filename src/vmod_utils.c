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

#include <cache/cache_varnishd.h>
#include "vas.h"
#include "vrt.h"
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

int
vmod_event_function(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
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

void* utils_init()
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
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
}

double __match_proto__()
vmod_real(struct sess *sp, const char *p, double d)
{
	char *e;
	double r;

	(void)sp;
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

const char*
vmod_hostname(struct sess * sp, struct vmod_priv *priv)
{
	struct vmod_utils_data* data = (struct vmod_utils_data*)priv->priv;
	(void)sp;
	return data->hostname;
}

const char*
vmod_timestamp(struct sess * sp)
{
	char *p;

	(void)sp;
	#define TIMESTAMP_LENGTH 64
	p = WS_Alloc(sp->http->ws, TIMESTAMP_LENGTH);
	if (p == NULL) {
		return "WS_Alloc_error";
	}
	snprintf(p, TIMESTAMP_LENGTH, "%.9f", TIM_real());
	return p;
}

unsigned int
vmod_exists(struct sess *sp, const char *path)
{
	struct stat st;

	(void)sp;
	return (stat(path, &st) == 0);
}

struct sockaddr_storage*
vmod_ip(struct sess *sp, const char *s, struct sockaddr_storage *d)
{
	struct addrinfo hints, *res0 = NULL;
	const struct addrinfo *res;
	int error;
	void *p;
	struct sockaddr_storage *r = NULL;
	static int l = sizeof(struct sockaddr_storage);

	(void)sp;
	AN(d);

	p = WS_Alloc(sp->http->ws, l);
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
		memcpy(r, d, l);
	}
	if (res0 != NULL)
		freeaddrinfo(res0);
	return (r);
}
