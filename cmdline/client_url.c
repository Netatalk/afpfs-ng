
#include <string.h>
#include "afp_server.h"
#include "afp_protocol.h"

/* This is wildly incomplete */

void default_url(struct afp_url *url)
{
	memset(url,'\0',sizeof(*url));
	url->port=548;
}

int parse_url(struct afp_url * url, char * toparse)
{

	if ((toparse,"%[^':']:%[^':']",
		url->hostname,url->volume)!=2)
			return -1;

	return 0;
}
