/*
 *  connect.c
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
#include "log.h"
#include "utils.h"
#include "uams_def.h"
#include "codepage.h"
#include "users.h"
#include "libafpclient_internal.h"
#include "server.h"

struct afp_server * afp_server_full_connect (struct client * c, struct afp_connection_request *req)
{
	int ret;
	struct sockaddr_in address;
	struct afp_server  * s=NULL;
	struct afp_server  * tmpserver;
	struct afp_volume * volume;
	char signature[AFP_SIGNATURE_LEN];
	unsigned char versions[SERVER_MAX_VERSIONS];
	unsigned int uams;
	char loginmesg[AFP_LOGINMESG_LEN];
	char machine_type[AFP_MACHINETYPE_LEN];
	char server_name[AFP_SERVER_NAME_LEN];
        char server_name_utf8[AFP_SERVER_NAME_UTF8_LEN];
	unsigned int rx_quantum;

	if (get_address(c,req->hostname, req->port,&address)<0) goto error;

	if ((s=find_server_by_address(&address))) goto have_server;

	if ((tmpserver=afp_server_init(&address))==NULL) goto error;

	if ((ret=afp_server_connect(tmpserver,1))<0) {
		afp_server_remove(tmpserver);
		libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
			"Could not connect, %s\n",strerror(-ret));
		goto error;
	}
	loop_disconnect(tmpserver);

	bcopy(&tmpserver->versions,&versions,SERVER_MAX_VERSIONS);
	uams=tmpserver->supported_uams;
	bcopy(&tmpserver->signature,signature,AFP_SIGNATURE_LEN);

	bcopy(&tmpserver->loginmesg,loginmesg,AFP_LOGINMESG_LEN);
	bcopy(&tmpserver->machine_type,machine_type,AFP_MACHINETYPE_LEN);
	bcopy(&tmpserver->server_name,server_name,AFP_SERVER_NAME_LEN);
	bcopy(&tmpserver->server_name_utf8,server_name_utf8,
		AFP_SERVER_NAME_UTF8_LEN);
	rx_quantum=tmpserver->rx_quantum;

	afp_server_remove(tmpserver);

	s=find_server_by_signature(signature);

	if (!s) {
		s = afp_server_init(&address);

		if (afp_server_connect(s,0) !=0) {
			libafpclient.log_for_client(c,AFPFSD,LOG_ERR,
				"Could not connect to server: %s\n",
				strerror(errno));
			goto error;
		}

		if ((afp_server_complete_connection(c,
			s,&address,&versions,uams,
			req->username, req->password, 
			req->requested_version, req->uam_mask))==NULL) 
			goto error;
		bcopy(loginmesg,s->loginmesg,AFP_LOGINMESG_LEN);
		bcopy(signature,s->signature,AFP_SIGNATURE_LEN);
		bcopy(server_name,s->server_name,AFP_SERVER_NAME_LEN);
                bcopy(server_name_utf8,s->server_name_utf8,
                        AFP_SERVER_NAME_UTF8_LEN);
		bcopy(machine_type,s->machine_type,AFP_MACHINETYPE_LEN);
		s->rx_quantum=rx_quantum;
	} 
have_server:
	convert_utf8dec_to_utf8pre(s->server_name_utf8,
		strlen(s->server_name_utf8),
		s->server_name_precomposed, AFP_SERVER_NAME_UTF8_LEN);

	/* Figure out if we're using netatalk */
	if (is_netatalk(s)) {
		s->server_type=AFPFS_SERVER_TYPE_NETATALK;
	} else {
		s->server_type=AFPFS_SERVER_TYPE_UNKNOWN;
	}

	return s;
error:
	if ((s) && (!something_is_mounted(s))) {
		afp_server_remove(s);
	}
	return NULL;
}

