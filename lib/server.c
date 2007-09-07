/*
 *  server.c
 *
 *  Copyright (C) 2007 Alex deVries
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/time.h>
#include <syslog.h>
#include <stdarg.h>
#include <getopt.h>
#include <signal.h>

#include "afp.h"
#include "dsi.h"
#include <fuse.h>
#include "log.h"
#include "utils.h"
#include "uams_def.h"
#include "codepage.h"
#include "users.h"
#include "libafpclient_internal.h"


struct afp_server * afp_server_complete_connection(
	struct client * c, 
	struct afp_server * server,
	struct sockaddr_in * address, unsigned char * versions,
		unsigned int uams, char * username, char * password, 
		unsigned int requested_version, unsigned int uam_mask)
{
	char loginmsg[AFP_LOGINMESG_LEN];
	int using_uam;

	bzero(loginmsg,AFP_LOGINMESG_LEN);

	libafpclient.log_for_client(c,AFPFSD,LOG_NOTICE,
		"Completing connection to server\n");

	server->requested_version=requested_version;
	bcopy(username,server->username,sizeof(server->username));
	bcopy(password,server->password,sizeof(server->password));

	add_fd_and_signal(server->fd);

printf("opening session\n");
	dsi_opensession(server);
printf("done opening session\n");

	/* Figure out what version we're using */
	if (((server->using_version=
		pick_version(versions,requested_version))==NULL)) {
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Server cannot handle AFP version %d\n",
			requested_version);
		goto error;
	}

	using_uam=pick_uam(uams,uam_mask);
	if (using_uam==-1) {
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Could not pick a matching UAM.\n");
		goto error;
	}
	server->using_uam=using_uam;
		
	if (server_login(c,server)) goto error;

	if (afp_getsrvrparms(server)) {
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Could not get server parameters\n");
		goto error;
	}

	afp_getsrvrmsg(server,AFPMESG_LOGIN,
		((server->using_version->av_number>=30)?1:0),1,loginmsg);  /* block */
	if (strlen(loginmsg)>0) 
		libafpclient.log_for_client(c,AFPFSD,LOG_NOTICE,
			"Login message: %s\n", loginmsg);


	return server;
error:
	afp_server_remove(server);
	return NULL;

}

int get_address(struct client * c, const char * hostname, unsigned int port, 
		struct sockaddr_in * address)
{
	struct hostent *h;

	h= gethostbyname(hostname);
	if (!h) {
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Could not resolve %s\n",hostname);
		goto error;
	}

	bzero(address,sizeof(*address));
	address->sin_family = AF_INET;
	address->sin_port = htons(port);
	memcpy(&address->sin_addr,h->h_addr,h->h_length);	
	return 0;
error:
	return -1;
}


int server_login(struct client * c, struct afp_server * server) 
{

	int rc;
	rc=afp_dologin(server,server->using_uam,
		server->username,server->password);
	switch(rc) {
	case -1:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Could not find a valid UAM when logging in\n");
		goto error;
	case kFPAuthContinue:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Authentication method unsupported by AFPFS\n");
		goto error;
	case kFPBadUAM:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Specified UAM is unknown\n");
		goto error;
	case kFPBadVersNum:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Server does not support this AFP version\n");
	case kFPCallNotSupported:
	case kFPMiscErr:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Already logged in\n");
		break;
	case kFPNoServer:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Authentication server not responding\n");
		goto error;
	case kFPPwdExpiredErr:
	case kFPPwdNeedsChangeErr:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Warning: password needs changing\n");
		goto error;
	case kFPServerGoingDown:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Server going down, so I can't log you in.\n");
		goto error;
	case kFPUserNotAuth:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Authentication failed\n");
		goto error;
	case 0: break;
	default:
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Unknown error, maybe username/passwd needed?\n");
		goto error;
	}
	return 0;
error:
	return 1;
}



