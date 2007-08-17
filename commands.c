/*
 *  commands.c
 *
 *  Copyright (C) 2006 Alex deVries
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
#include <fuse.h>
#include "dsi.h"
#include "afp_server.h"
#include "log.h"
#include "utils.h"
#include "daemon.h"
#include "uams_def.h"
#include "codepage.h"
#include "users.h"

void trigger_exit(void);

struct client {
	char incoming_string[1024];
	int incoming_size;
	char client_string[sizeof(struct afp_server_response) + MAX_CLIENT_RESPONSE];
	int fd;
	struct client * next;
};
static struct client * client_base = NULL;

struct afp_volume * global_volume;


void just_end_it_now(void);
static int volopen(struct client * c, struct afp_volume * volume);
static int process_command(struct client * c);
static struct afp_volume * mount_volume(struct client * c,
	struct afp_server * server, char * volname, char * volpassword) ;


static int remove_client(struct client * toremove) 
{
	struct client * c, * prev=NULL;

	for (c=client_base;c;c=c->next) {
		if (c==toremove) {
			if (!prev) client_base=NULL;
			else prev->next=toremove->next;
			free(toremove);
			toremove=NULL;
			return 0;
		}
		prev=c;
	}
	return -1;
}

int add_client(int fd) 
{
	struct client * c, *newc;

	if ((newc=malloc(sizeof(*newc)))==NULL) goto error;


	bzero(newc,sizeof(*newc));
	newc->fd=fd;
	newc->next=NULL;
	if (client_base==NULL) client_base=newc;
	else {
		for (c=client_base;c->next;c=c->next);
		c->next=newc;

	}
	return 0;
error:
	return -1;
}

int process_client_fds(fd_set * set, int max_fd, int ** onfd)
{

	struct client * c;

	for (c=client_base;c;c=c->next) {
		if (FD_ISSET(c->fd,set)) {
			if (process_command(c)<0) return -1;
			return 1;
		}
	}
	return 0;

}

void log_for_client(struct client * c, 
	enum loglevels loglevel, int logtype, char *message, ...) {
	va_list args;
	char new_message[1024];
	int len = 0;
	va_start(args, message);
	vsnprintf(new_message,1024,message,args);
	va_end(args);

	len = strlen(c->client_string);


	snprintf(c->client_string+len,
		MAX_CLIENT_RESPONSE-len,
		new_message);
	/* Finished with args for now */
	va_end(args);
	LOG(loglevel,logtype,"%s",new_message);
}

static void * start_fuse_thread(void * other) 
{
	int ret=0;
	int fuseargc=0;
	const char *fuseargv[200];
	struct afp_volume * volume = other;
	struct afp_server * server = volume->server;
#define mountstring_len (AFP_SERVER_NAME_LEN+1+AFP_VOLUME_NAME_LEN+1)
	char mountstring[mountstring_len];

	snprintf(mountstring,mountstring_len,"%s:%s",
		server->server_name,volume->name);

	fuseargc=0;
	fuseargv[0]=mountstring;
	fuseargc++;
	fuseargv[1]=volume->mountpoint;
	fuseargc++;
	if (get_debug_mode()) {
		fuseargv[fuseargc]="-d";
		fuseargc++;
	} else {
		fuseargv[fuseargc]="-f";
		fuseargc++;
	}

#define USE_SINGLE_THREAD
#ifdef USE_SINGLE_THREAD
	fuseargv[fuseargc]="-s";
	fuseargc++;
#endif
	global_volume=volume; 

	ret=afp_register_fuse(fuseargc, fuseargv,volume);

	volume->mount_errno=errno;
	pthread_cond_signal(&volume->startup_condition_cond);
	afp_unmount_volume(volume);

	return NULL;
}

static int volopen(struct client * c, struct afp_volume * volume)
{
	char mesg[1024];
	unsigned int l = 1024;	
	int rc=afp_connect_volume(volume,mesg,&l,1024);

	if (rc) 
		log_for_client(c,AFPFSD,LOG_ERR,"%s",mesg);
	return rc;

}

static int login(struct client * c, struct afp_server * server) 
{

	int rc;
	rc=afp_dologin(server,server->using_uam,
		server->username,server->password);
	switch(rc) {
	case -1:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not find a valid UAM\n");
		goto error;
	case kFPAuthContinue:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Authentication method unsupported by AFPFS\n");
		goto error;
	case kFPBadUAM:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Specified UAM is unknown\n");
		goto error;
	case kFPBadVersNum:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Server does not support this AFP version\n");
	case kFPCallNotSupported:
	case kFPMiscErr:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Already logged in\n");
		break;
	case kFPNoServer:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Authentication server not responding\n");
		goto error;
	case kFPPwdExpiredErr:
	case kFPPwdNeedsChangeErr:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Warning: password needs changing\n");
		goto error;
	case kFPServerGoingDown:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Server going down, so I can't log you in.\n");
		goto error;
	case kFPUserNotAuth:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Authentication failed\n");
		goto error;
	case 0: break;
	default:
		log_for_client(c,AFPFSD,LOG_ERR,
			"Unknown error, maybe username/passwd needed?\n");
		goto error;
	}
	return 0;
error:
	return 1;
}

static struct afp_server * connect_to_new_server(
	struct client * c, 
	struct sockaddr_in *address,
	struct afp_server_mount_request * req)
{
	struct afp_server * server;

	log_for_client(c,AFPFSD,LOG_NOTICE,
		"Creating new connection to server\n");

	server = afp_server_init(address);

	if (!server) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Error preparing for connection to server: %s\n",
			strerror(errno));
		goto error;
	}
	if (afp_server_connect(server) !=0) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not connect to server: %s\n",
			strerror(errno));
		goto error;
	}
	add_server(server);
	server->requested_version=req->requested_version;
	bcopy(req->username,server->username,sizeof(server->username));
	bcopy(req->password,server->password,sizeof(server->password));

	return server;
error:
	return NULL;

}


static struct afp_server * new_server(
	struct client * c, 
	struct sockaddr_in * address, unsigned char * versions,
		unsigned int uams, struct afp_server_mount_request * req) 
{
	struct afp_server * server;
	char loginmsg[AFP_LOGINMESG_LEN];
	int using_uam;

	bzero(loginmsg,AFP_LOGINMESG_LEN);

	if ((server=connect_to_new_server(c,address,req))==NULL) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not connect to server: %s\n",
			strerror(errno));
		return NULL;
	}
	add_fd_and_signal(server->fd);

	dsi_opensession(server);

	/* Figure out what version we're using */
	if (((server->using_version=
		pick_version(versions,req->requested_version))==NULL)) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Server cannot handle AFP version %d\n",
			server->requested_version);
		goto error;
	}

	using_uam=pick_uam(uams,req->uam_mask);
	if (using_uam==-1) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not find matching UAM.\n");
		goto error;
	}
	server->using_uam=using_uam;
		
	if (login(c,server)) goto error;

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

static int get_address(struct client * c, struct afp_server_mount_request *req, 
		struct sockaddr_in * address)
{
	struct hostent *h;

	h= gethostbyname(req->hostname);
	if (!h) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not resolve %s\n",req->hostname);
		goto error;
	}

	bzero(address,sizeof(*address));
	address->sin_family = AF_INET;
	address->sin_port = htons(req->port);
	memcpy(&address->sin_addr,h->h_addr,h->h_length);	
	return 0;
error:
	return -1;
}

static int mount_getstatus(struct client * c, struct afp_server * server, 
		struct sockaddr_in *address)
{
	struct timeval t1, t2;
	int sock;
	int ret=0;

	if ((sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP))<0) {
		ret=-errno;
		goto error;
	}
	if ((connect(sock,(struct sockaddr*) address,
		sizeof(struct sockaddr_in)))<0) {
			ret=-errno;
			goto error;
	}
	server->connect_state=SERVER_STATE_CONNECTED;
	server->fd=sock;
	add_fd_and_signal(sock);

	/* Get the status, and calculate the transmit time.  We use this to
	   calculate our rx quantum. */
	gettimeofday(&t1,NULL);
	dsi_getstatus(server);
	gettimeofday(&t2,NULL);
	if ((t2.tv_sec - t1.tv_sec) > 0) 
		server->tx_delay= (t2.tv_sec - t1.tv_sec) * 1000;
	else 
		server->tx_delay= (t2.tv_usec - t1.tv_usec) / 1000;

	/* Calculate the quantum based on our tx_delay and a threshold */
	/* For now, we'll just set a default */
	/* This is the default in 10.4.x where x > 7 */
	server->rx_quantum = 128 * 1024;
	afp_server_disconnect(server);
error:
	return ret;
}


static unsigned char process_suspend(struct client * c)
{
	struct afp_server_suspend_request * req =(void *)c->incoming_string+1;
	struct afp_server * s;

	/* Find the server */
	if ((s=find_server_by_name(req->server_name))==NULL) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}

	if (afp_zzzzz(s)) 
		return AFP_SERVER_RESULT_ERROR;

	afp_server_disconnect(s);
	s->connect_state=SERVER_STATE_SUSPENDED;
	log_for_client(c,AFPFSD,LOG_NOTICE,
		"Disconnected from %s\n",req->server_name);
	return AFP_SERVER_RESULT_OKAY;
}

static int afp_server_reconnect_loud(struct client * c, struct afp_server * s) 
{
	char mesg[1024];
	unsigned int l = 2040;
	int rc;

	rc=afp_server_reconnect(s,mesg,&l,l);

	if (rc) 
                log_for_client(c,AFPFSD,LOG_ERR,
                        "%s",mesg);
	return rc;


}



static unsigned char process_resume(struct client * c)
{
	struct afp_server_resume_request * req =(void *) c->incoming_string+1;
	struct afp_server * s;

	/* Find the server */
	if ((s=find_server_by_name(req->server_name))==NULL) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}

	if (afp_server_reconnect_loud(c,s)) 
	{
		log_for_client(c,AFPFSD,LOG_ERR,
			"Unable to reconnect to %s\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}
	log_for_client(c,AFPFSD,LOG_NOTICE,
		"Resumed connection to %s\n",req->server_name);

	return AFP_SERVER_RESULT_OKAY;
	
}

static unsigned char process_unmount(struct client * c)
{
	struct afp_server_unmount_request * req;
	struct afp_server * s;
	struct afp_volume * v;
	int j=0;

	req=(void *) c->incoming_string+1;

	for (s=get_server_base();s;s=s->next) {
		for (j=0;j<s->num_volumes;j++) {
			v=&s->volumes[j];
			if (strcmp(v->mountpoint,req->mountpoint)==0) {
				goto found;
			}

		}
	}
	goto notfound;
found:
	if (v->mounted != AFP_VOLUME_MOUNTED ) {
		log_for_client(c,AFPFSD,LOG_NOTICE,
			"%s was not mounted\n",v->mountpoint);
		return AFP_SERVER_RESULT_ERROR;
	}

	afp_unmount_volume(v);

	return AFP_SERVER_RESULT_OKAY;
notfound:
	log_for_client(c,AFPFSD,LOG_WARNING,
		"%s is not mounted\n",req->mountpoint);
	return AFP_SERVER_RESULT_ERROR;


}

static unsigned char process_exit(struct client * c)
{
	log_for_client(c,AFPFSD,LOG_INFO,
		"Exiting\n");
	trigger_exit();
	return AFP_SERVER_RESULT_OKAY;
}

static unsigned char process_status(struct client * c)
{
	int j;
	struct afp_volume *v;
	struct afp_server * s;
	char tmpvolname[AFP_VOLUME_NAME_LEN];

	if ((c->incoming_size + 1)< sizeof(struct afp_server_status_request)) 
		return AFP_SERVER_RESULT_ERROR;

	log_for_client(c,AFPFSD,LOG_INFO,
		"AFPFS Version: %s\n"
		"UAMs compiled in: %s\n",
		AFPFS_VERSION,
		get_uam_names_list());

	s=get_server_base();

	if (!s) {
		log_for_client(c,AFPFSD,LOG_INFO,
			"Not connected to any servers\n");
		return AFP_SERVER_RESULT_OKAY;
	}
	
	for (s=get_server_base();s;s=s->next) {
		log_for_client(c,AFPFSD,LOG_DEBUG,
			"Server %s\n"
			"    connection: %s:%d %s\n"
			"    AFP version: %s\n"
			"    using UAM: %s\n"
			"    login message: %s\n"
			"    type: %s\n"
			"    signature: %s\n"
			"    transmit delay: %ums\n"
			"    quantums: %u(tx) %u(rx)\n"
			"    last request id: %d in queue: %llu\n"
			"    transfer: %llu(rx) %llu(tx)\n"
			"    runt packets: %llu\n",
		s->server_name,
		inet_ntoa(s->address.sin_addr),ntohs(s->address.sin_port),
			(s->connect_state==SERVER_STATE_SUSPENDED ? 
			"SUSPENDED" : "(active)"),
		s->using_version->av_name,
		uam_bitmap_to_string(s->using_uam),
		s->loginmesg,
		s->machine_type, s->signature,
		s->tx_delay,
		s->tx_quantum, s->rx_quantum,
		s->lastrequestid,s->stats.requests_pending,
		s->stats.rx_bytes,s->stats.tx_bytes,
		s->stats.runt_packets);
		{
			struct dsi_request * r;
			for (r=s->command_requests;r;r=r->next) 
			log_for_client(c,AFPFSD,LOG_DEBUG,
			"        outstanding packet command: %d: %d\n",
			r->requestid,r->subcommand);
		}
				
		for (j=0;j<s->num_volumes;j++) {
			v=&s->volumes[j];
			convert_utf8dec_to_utf8pre(v->name,strlen(v->name),
				tmpvolname,AFP_VOLUME_NAME_LEN);
			log_for_client(c,AFPFSD,LOG_DEBUG,
			"    Volume %s, id %d, attribs 0x%x mounted: %s\n",
			tmpvolname,v->volid,
			v->attributes,
			(v->mounted==AFP_VOLUME_MOUNTED) ? v->mountpoint:"No");

			if (v->mounted==AFP_VOLUME_MOUNTED) 
				log_for_client(c,AFPFSD,LOG_DEBUG,
				"        did cache stats: %llu miss, %llu hit, %llu expired, %llu force removal\n        mapping: %s\n",
				v->did_cache_stats.misses, v->did_cache_stats.hits,
				v->did_cache_stats.expired, 
				v->did_cache_stats.force_removed,
				get_mapping_name(v));
			log_for_client(c,AFPFSD,LOG_DEBUG,"\n");
		}
	}

	return AFP_SERVER_RESULT_OKAY;

}

static int process_mount(struct client * c)
{
	struct afp_server_mount_request * req;
	int ret;
	struct sockaddr_in address;
	struct afp_server  * s=NULL;
	struct afp_server  * tmpserver;
	struct afp_volume * volume;
	char signature[16];
	unsigned char versions[SERVER_MAX_VERSIONS];
	unsigned int uams;
	char loginmesg[AFP_LOGINMESG_LEN];
	char machine_type[AFP_MACHINETYPE_LEN];
	char server_name[AFP_SERVER_NAME_LEN];
	unsigned int rx_quantum;

	if ((c->incoming_size-1) < sizeof(struct afp_server_mount_request)) {
		goto error;
	}

	req=(void *) c->incoming_string+1;

	/* Todo should check the existance and perms of the mount point */

	log_for_client(c,AFPFSD,LOG_NOTICE,
		"mounting %s on %s\n",(char *) req->volume,req->mountpoint);

	if (get_address(c,req,&address)<0) goto error;

	if ((s=find_server_by_address(&address))) goto have_server;

	/* Check the server signature */
	if ((tmpserver=malloc(sizeof(*tmpserver)))==NULL) goto error;

	bzero(tmpserver,sizeof(*tmpserver));
	tmpserver->incoming_buffer=malloc(2048);
	tmpserver->bufsize=2048;
	add_server(tmpserver);
	if ((ret=mount_getstatus(c,tmpserver,&address))<0) {
		afp_server_remove(tmpserver);
		log_for_client(c,AFPFSD,LOG_ERR,
			"Could not mount, %s\n",strerror(-ret));
		goto error;
	}

	bcopy(&tmpserver->versions,&versions,SERVER_MAX_VERSIONS);
	uams=tmpserver->supported_uams;
	bcopy(&signature,&tmpserver->signature,16);
	bcopy(&tmpserver->loginmesg,loginmesg,AFP_LOGINMESG_LEN);
	bcopy(&tmpserver->machine_type,machine_type,AFP_MACHINETYPE_LEN);
	bcopy(&tmpserver->server_name,server_name,AFP_SERVER_NAME_LEN);
	rx_quantum=tmpserver->rx_quantum;
	afp_server_remove(tmpserver);

	s=find_server_by_signature(signature);
	log_for_client(c,AFPFSD,LOG_DEBUG, "Starting mount.\n");

	if (!s) {
		if ((s=new_server(c,&address,&versions,uams,req))==NULL) 
			goto error;
		bcopy(loginmesg,s->loginmesg,AFP_LOGINMESG_LEN);
		bcopy(server_name,s->server_name,AFP_SERVER_NAME_LEN);
		bcopy(machine_type,s->machine_type,AFP_MACHINETYPE_LEN);
		s->rx_quantum=rx_quantum;
	} 
have_server:
	/* Figure out if we're using netatalk */
	if (is_netatalk(s)) {
		s->server_type=AFPFS_SERVER_TYPE_NETATALK;
	} else {
		s->server_type=AFPFS_SERVER_TYPE_UNKNOWN;
	}
	log_for_client(c,AFPFSD,LOG_DEBUG, "Actually mounting.\n");
	if ((volume=mount_volume(c,s,req->volume,req->volpassword))==NULL) {
		goto error;
	}

	volume->options=req->volume_options;
	snprintf(volume->mountpoint,255,req->mountpoint);


	/* Create the new thread and block until we get an answer back */
	{
		pthread_mutex_t mutex;
		struct timespec ts;
		struct timeval tv;
		gettimeofday(&tv,NULL);
		ts.tv_sec=tv.tv_sec;
		ts.tv_sec+=5;
		ts.tv_nsec=tv.tv_usec*1000;
		pthread_mutex_init(&mutex,NULL);
		pthread_cond_init(&volume->startup_condition_cond,NULL);


		pthread_create(&volume->thread,NULL,start_fuse_thread,volume);

		switch(pthread_cond_timedwait(&volume->startup_condition_cond,&mutex,&ts)) {
		case 0:
		if (volume->mounted==AFP_VOLUME_UNMOUNTED) {
			/* Try and discover why */
			switch(volume->mount_errno) {
			case ENOENT:
				log_for_client(c,AFPFSD,LOG_ERR,
					"Permission denied, maybe a problem with the fuse device or mountpoint?\n");
				break;
			default:
				log_for_client(c,AFPFSD,LOG_ERR,
					"Mounting failed.\n");
			}
			goto error;
		} else {
			log_for_client(c,AFPFSD,LOG_NOTICE,
				"Mounting succeeded.\n");
			return 0;
		}
		break;
		case ETIMEDOUT:
			log_for_client(c,AFPFSD,LOG_NOTICE,
				"Still trying.\n");
			return 0;
			break;
		break;
		default:
			log_for_client(c,AFPFSD,LOG_NOTICE,
				"Unknown error.\n");
			goto error;
		}

	}
	return AFP_SERVER_RESULT_OKAY;
error:
	if ((s) && (!something_is_mounted(s))) {
		afp_server_remove(s);
	}
	signal_main_thread();
	return AFP_SERVER_RESULT_ERROR;
}


static void * process_command_thread(void * other)
{

	struct client * c = other;
	int ret=0;
	char tosend[sizeof(struct afp_server_response) + MAX_CLIENT_RESPONSE];
	struct afp_server_response response;

	switch(c->incoming_string[0]) {
	case AFP_SERVER_COMMAND_MOUNT: 
		ret=process_mount(c);
		break;
	case AFP_SERVER_COMMAND_STATUS: 
		ret=process_status(c);
		break;
	case AFP_SERVER_COMMAND_UNMOUNT: 
		ret=process_unmount(c);
		break;
	case AFP_SERVER_COMMAND_SUSPEND: 
		ret=process_suspend(c);
		break;
	case AFP_SERVER_COMMAND_RESUME: 
		ret=process_resume(c);
		break;
	case AFP_SERVER_COMMAND_EXIT: 
		ret=process_exit(c);
		break;
	default:
		log_for_client(c,AFPFSD,LOG_ERR,"Unknown command\n");
	}
	/* Send response */
	response.result=ret;
	response.len=strlen(c->client_string);

	bcopy(&response,tosend,sizeof(response));
	bcopy(c->client_string,tosend+sizeof(response),response.len);
	ret=write(c->fd,tosend,sizeof(response)+response.len);
	if (ret<0) {
		perror("Writing");
	}

	if ((!c) || (c->fd==0)) return NULL;
	rm_fd_and_signal(c->fd);
	close(c->fd);
	remove_client(c);

	return NULL;

}
static int process_command(struct client * c)
{
	int ret;
	int fd;

	ret=read(c->fd,&c->incoming_string,1024);
	if (ret<=0) {
		perror("reading");
		goto out;
	}
	c->incoming_size=ret;

	pthread_t thread;
	pthread_create(&thread,NULL,process_command_thread,c);
	return 0;
out:
	fd=c->fd;
	c->fd=0;
	remove_client(c);
	close(fd);
	rm_fd_and_signal(fd);
	return 0;
}


static struct afp_volume * mount_volume(struct client * c,
	struct afp_server * server, char * volname, char * volpassword) 
{
	int i;
	struct afp_volume * using_volume=NULL;
	char converted_volname[AFP_VOLUME_NAME_LEN];

	convert_utf8pre_to_utf8dec(volname,strlen(volname),
		converted_volname,AFP_VOLUME_NAME_LEN);

	for (i=0;i<server->num_volumes;i++) 
		if (strcmp(converted_volname,server->volumes[i].name)==0) {
			using_volume=&server->volumes[i];
		}

	if (!using_volume) {
		log_for_client(c,AFPFSD,LOG_ERR,
			"Volume %s does not exist on server.\n",volname);
		if (server->num_volumes) {
			log_for_client(c,AFPFSD,LOG_ERR,"Choose from:\n");
			for (i=0;i<server->num_volumes;i++) 
				log_for_client(c,AFPFSD,LOG_ERR,"   %s\n",
					server->volumes[i].name);
		}
		goto error;
	}

	if (using_volume->mounted==AFP_VOLUME_MOUNTED) {
		log_for_client(c,AFPFSD,LOG_ERR,"Volume %s is already mounted\n",volname);
		goto error;
	}

	if (using_volume->flags & HasPassword) {
		bcopy(volpassword,using_volume->volpassword,AFP_VOLPASS_LEN);
		if (strlen(volpassword)<1) {
			log_for_client(c,AFPFSD,LOG_ERR,"Volume password needed\n");
			goto error;
		}
	}  else bzero(using_volume->volpassword,AFP_VOLPASS_LEN);

	if (volopen(c,using_volume)) {
		log_for_client(c,AFPFSD,LOG_ERR,"Could not mount volume %s\n",volname);
		goto error;
	}

	if (using_volume->attributes & kSupportsUTF8Names) 
		server->path_encoding=kFPUTF8Name; 
	else 
		server->path_encoding=kFPLongName;

	/* Figure out the name mapping TODO */


	using_volume->server=server;

	afp_detect_mapping(using_volume);

	return using_volume;
error:
	return NULL;
}


