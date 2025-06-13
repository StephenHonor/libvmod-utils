#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cache/cache_varnishd.h>
#include "vas.h"
#include "vrt.h"
#include "bin/varnishd/cache.h"

int
init_function(struct vmod_priv *priv, const struct VCL_conf *conf)
{
	return (0);
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
