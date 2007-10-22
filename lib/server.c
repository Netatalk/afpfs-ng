/*
 *  server.c
 *
 *  Copyright (C) 2007 Alex deVries
 *
 */

#include <string.h>

#include "afp.h"
#include "dsi.h"
#include "afpclient_log.h"
#include "utils.h"
#include "uams_def.h"
#include "codepage.h"
#include "users.h"
#include "libafpclient.h"


struct afp_server * afp_server_complete_connection(
	struct client * c, 
	struct afp_server * server,
	struct sockaddr_in * address, unsigned char * versions,
		unsigned int uams, char * username, char * password, 
		unsigned int requested_version, unsigned int uam_mask)
{
	char loginmsg[AFP_LOGINMESG_LEN];
	int using_uam;
	char mesg[1024];
	int len;

	bzero(loginmsg,AFP_LOGINMESG_LEN);

	log_for_client(c,AFPFSD,LOG_NOTICE,
		"Completing connection to server\n");
	server->requested_version=requested_version;
	bcopy(username,server->username,sizeof(server->username));
	bcopy(password,server->password,sizeof(server->password));

	add_fd_and_signal(server->fd);

	dsi_opensession(server);

	/* Figure out what version we're using */
	if (((server->using_version=
		pick_version(versions,requested_version))==NULL)) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Server cannot handle AFP version %d\n",
			requested_version);
		goto error;
	}

	using_uam=pick_uam(uams,uam_mask);
	if (using_uam==-1) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not pick a matching UAM.\n");
		goto error;
	}
	server->using_uam=using_uam;
		
	if (afp_server_login(server,mesg,&len)) goto error;

	if (afp_getsrvrparms(server)) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not get server parameters\n");
		goto error;
	}

	afp_getsrvrmsg(server,AFPMESG_LOGIN,
		((server->using_version->av_number>=30)?1:0),1,loginmsg);  /* block */
	if (strlen(loginmsg)>0) 
		log_for_client(c,AFPFSD,LOG_NOTICE,
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
		log_for_client(c,AFPFSD,LOG_ERR,
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


