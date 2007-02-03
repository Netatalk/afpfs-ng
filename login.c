

/*
 *  login.c
 *
 *  Copyright (C) 2006 Alex deVries
 *
 */

#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "dsi.h"
#include "afp.h"
#include "utils.h"
#include "log.h"


int afp_logout(struct afp_server *server, unsigned char wait) 
{
	struct {
		struct dsi_header dsi_header __attribute__((__packed__));
		uint8_t command;
		uint8_t pad;
	}  __attribute__((__packed__)) request;
	dsi_setup_header(server,&request.dsi_header,DSI_DSICommand);
	request.command=afpLogout;
	request.pad=0;
	return dsi_send(server, (char *) &request,sizeof(request),
	wait,afpLogout,NULL);
}


int afp_login(struct afp_server *server, char * ua_name, 
	char * userauthinfo, unsigned char userauthinfo_len)
{

	char * msg;
	char * p;
	int ret;
	struct {
		struct dsi_header header __attribute__((__packed__));
		uint8_t command;
	}  __attribute__((__packed__)) * request;
	unsigned int len = 
		sizeof(*request) /* DSI Header */
		+ strlen(server->using_version->av_name) + 1 /* Version */
		+ strlen(ua_name) + 1   /* UAM */
		+ userauthinfo_len;

	msg = malloc(len);
	if (!msg) return -1;
	request = (void *) msg;
	p=msg+(sizeof(*request));

	dsi_setup_header(server,&request->header,DSI_DSICommand);
	request->command=afpLogin;
	p +=copy_to_pascal(p,server->using_version->av_name)+1;
	p +=copy_to_pascal(p,ua_name)+1;

	bcopy(userauthinfo,p,userauthinfo_len);

	ret=dsi_send(server, (char *) msg,len,1,afpLogin,NULL);
	free(msg);
	
	return ret;
}

