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

#include "afpclient_log.h"
#include "afp.h"
#include "dsi.h"
#include <fuse.h>
#include "afp_server.h"
#include "utils.h"
#include "daemon.h"
#include "uams_def.h"
#include "codepage.h"
#include "users.h"
#include "libafpclient.h"
#include "server.h"
#include "map_def.h"
#include "fuse_int.h"

void trigger_exit(void);

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

static int fuse_add_client(int fd) 
{
	struct client * c, *newc;

	LOG(AFPFSD,LOG_DEBUG,
		"Got connection %d\n",fd);

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

static int fuse_process_client_fds(fd_set * set, int max_fd)
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

int fuse_scan_extra_fds(int command_fd, fd_set *set, int * max_fd)
{

	struct sockaddr_un new_addr;
	socklen_t new_len = sizeof(struct sockaddr_un);
	int new_fd;


	if (FD_ISSET(command_fd,set)) {
		new_fd=accept(command_fd,(struct sockaddr *) &new_addr,&new_len);
		if (new_fd>=0) {
			fuse_add_client(new_fd);
			FD_SET(new_fd,set);
			if ((new_fd+1) > *max_fd) *max_fd=new_fd+1;
		}
	}

	switch (fuse_process_client_fds(set,*max_fd)) {
	case -1:
		{
			int i;
			FD_CLR(new_fd,set);
			for (i=*max_fd;i>=0;i--)
				if (FD_ISSET(i,set)) {
					*max_fd=i;
					break;
				}
		}

		(*max_fd)++;
		close(new_fd);
		goto out;
	case 1:
		goto out;
	}
	LOG(AFPFSD,LOG_ERR,
		"**** Unknown fd\n");
	sleep(10);

	return 0;

out:
	return 1;
}

void fuse_log_for_client(struct client * c, 
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
	char volume_precomposed[AFP_VOLUME_NAME_UTF8_LEN];

	convert_utf8dec_to_utf8pre(volume->name,
		strlen(volume->name),
		volume_precomposed, AFP_VOLUME_NAME_UTF8_LEN);


	snprintf(mountstring,mountstring_len,"%s:%s",
		server->server_name_precomposed,volume_precomposed);

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

	ret=afp_register_fuse(fuseargc, (char **) fuseargv,volume);

	volume->mount_errno=errno;
	pthread_cond_signal(&volume->startup_condition_cond);
	afp_unmount_volume(volume);

	return NULL;
}

static int volopen(struct client * c, struct afp_volume * volume)
{
	char mesg[1024];
	unsigned int l = 1024;	
	int rc=afp_connect_volume(volume,volume->server,mesg,&l,1024);

	if (rc) 
		fuse_log_for_client(c,AFPFSD,LOG_ERR,"%s",mesg);
	return rc;

}


static unsigned char process_suspend(struct client * c)
{
	struct afp_server_suspend_request * req =(void *)c->incoming_string+1;
	struct afp_server * s;

	/* Find the server */
	if ((s=find_server_by_name(req->server_name))==NULL) {
		fuse_log_for_client(c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}

	if (afp_zzzzz(s)) 
		return AFP_SERVER_RESULT_ERROR;

	loop_disconnect(s);
	
	s->connect_state=SERVER_STATE_DISCONNECTED;
	fuse_log_for_client(c,AFPFSD,LOG_NOTICE,
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
                fuse_log_for_client(c,AFPFSD,LOG_ERR,
                        "%s",mesg);
	return rc;


}



static unsigned char process_resume(struct client * c)
{
	struct afp_server_resume_request * req =(void *) c->incoming_string+1;
	struct afp_server * s;

	/* Find the server */
	if ((s=find_server_by_name(req->server_name))==NULL) {
		fuse_log_for_client(c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}

	if (afp_server_reconnect_loud(c,s)) 
	{
		fuse_log_for_client(c,AFPFSD,LOG_ERR,
			"Unable to reconnect to %s\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}
	fuse_log_for_client(c,AFPFSD,LOG_NOTICE,
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
		fuse_log_for_client(c,AFPFSD,LOG_NOTICE,
			"%s was not mounted\n",v->mountpoint);
		return AFP_SERVER_RESULT_ERROR;
	}

	afp_unmount_volume(v);

	return AFP_SERVER_RESULT_OKAY;
notfound:
	fuse_log_for_client(c,AFPFSD,LOG_WARNING,
		"%s is not mounted\n",req->mountpoint);
	return AFP_SERVER_RESULT_ERROR;


}

static unsigned char process_exit(struct client * c)
{
	fuse_log_for_client(c,AFPFSD,LOG_INFO,
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
	char signature_string[AFP_SIGNATURE_LEN*2+1];

	if ((c->incoming_size + 1)< sizeof(struct afp_server_status_request)) 
		return AFP_SERVER_RESULT_ERROR;

	fuse_log_for_client(c,AFPFSD,LOG_INFO,
		"AFPFS Version: %s\n"
		"UAMs compiled in: %s\n",
		AFPFS_VERSION,
		get_uam_names_list());

	s=get_server_base();

	if (!s) {
		for (j=0;j<AFP_SIGNATURE_LEN;j++)
			sprintf(signature_string+(j*2),"%02x",
				(unsigned int) ((char) s->signature[j]));

		fuse_log_for_client(c,AFPFSD,LOG_INFO,
			"Not connected to any servers\n");
		return AFP_SERVER_RESULT_OKAY;
	}
	
	for (s=get_server_base();s;s=s->next) {
		fuse_log_for_client(c,AFPFSD,LOG_DEBUG,
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
		s->server_name_precomposed,
		inet_ntoa(s->address.sin_addr),ntohs(s->address.sin_port),
			(s->connect_state==SERVER_STATE_DISCONNECTED ? 
			"Disconnected" : "(active)"),
		s->using_version->av_name,
		uam_bitmap_to_string(s->using_uam),
		s->loginmesg,
		s->machine_type, signature_string,
		s->tx_delay,
		s->tx_quantum, s->rx_quantum,
		s->lastrequestid,s->stats.requests_pending,
		s->stats.rx_bytes,s->stats.tx_bytes,
		s->stats.runt_packets);
		{
			struct dsi_request * r;
			for (r=s->command_requests;r;r=r->next) 
			fuse_log_for_client(c,AFPFSD,LOG_DEBUG,
			"        outstanding packet command: %d: %d\n",
			r->requestid,r->subcommand);
		}
				
		for (j=0;j<s->num_volumes;j++) {
			v=&s->volumes[j];
			convert_utf8dec_to_utf8pre(v->name,strlen(v->name),
				tmpvolname,AFP_VOLUME_NAME_LEN);
			fuse_log_for_client(c,AFPFSD,LOG_DEBUG,
			"    Volume %s, id %d, attribs 0x%x mounted: %s\n",
			tmpvolname,v->volid,
			v->attributes,
			(v->mounted==AFP_VOLUME_MOUNTED) ? v->mountpoint:"No");

			if (v->mounted==AFP_VOLUME_MOUNTED) 
				fuse_log_for_client(c,AFPFSD,LOG_DEBUG,
				"        did cache stats: %llu miss, %llu hit, %llu expired, %llu force removal\n        uid/gid mapping: %s (%d/%d)\n",
				v->did_cache_stats.misses, v->did_cache_stats.hits,
				v->did_cache_stats.expired, 
				v->did_cache_stats.force_removed,
				get_mapping_name(v),
				s->server_uid,s->server_gid);
			fuse_log_for_client(c,AFPFSD,LOG_DEBUG,"\n");
		}
	}

	return AFP_SERVER_RESULT_OKAY;

}

static int process_mount(struct client * c)
{
	struct afp_server_mount_request * req;
	struct afp_server  * s=NULL;
	struct afp_volume * volume;
	struct afp_connection_request conn_req;

	if ((c->incoming_size-1) < sizeof(struct afp_server_mount_request)) {
		goto error;
	}

	req=(void *) c->incoming_string+1;

	/* Todo should check the existance and perms of the mount point */

	fuse_log_for_client(c,AFPFSD,LOG_NOTICE,
		"mounting %s on %s\n",(char *) req->volume,req->mountpoint);

	bzero(&conn_req,sizeof(conn_req));

	conn_req.requested_version=req->requested_version;
	conn_req.uam_mask=req->uam_mask;
	bcopy(&req->username,&conn_req.username,AFP_MAX_USERNAME_LEN);
	bcopy(&req->password,&conn_req.password,AFP_MAX_PASSWORD_LEN);
	bcopy(&req->hostname,&conn_req.hostname,255);
	conn_req.port=req->port;

	if ((s=afp_server_full_connect(c,&conn_req))==NULL) {
		signal_main_thread();
		goto error;
	}
	
	fuse_log_for_client(c,AFPFSD,LOG_DEBUG, "Actually mounting.\n");
	if ((volume=mount_volume(c,s,req->volume,req->volpassword))==NULL) {
		goto error;
	}

	volume->options=req->volume_options;

	volume->mapping=req->map;
	afp_detect_mapping(volume);

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
				fuse_log_for_client(c,AFPFSD,LOG_ERR,
					"Permission denied, maybe a problem with the fuse device or mountpoint?\n");
				break;
			default:
				fuse_log_for_client(c,AFPFSD,LOG_ERR,
					"Mounting failed.\n");
			}
			goto error;
		} else {
			fuse_log_for_client(c,AFPFSD,LOG_NOTICE,
				"Mounting succeeded.\n");
			return 0;
		}
		break;
		case ETIMEDOUT:
			fuse_log_for_client(c,AFPFSD,LOG_NOTICE,
				"Still trying.\n");
			return 0;
			break;
		break;
		default:
			fuse_log_for_client(c,AFPFSD,LOG_NOTICE,
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
		fuse_log_for_client(c,AFPFSD,LOG_ERR,"Unknown command\n");
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

	memset(converted_volname,0,AFP_VOLUME_NAME_LEN);

	convert_utf8pre_to_utf8dec(volname,strlen(volname),
		converted_volname,AFP_VOLUME_NAME_LEN);

	for (i=0;i<server->num_volumes;i++)  {
		if (strcmp(converted_volname,server->volumes[i].name)==0) {
			using_volume=&server->volumes[i];
		}
	}

	if (!using_volume) {
		fuse_log_for_client(c,AFPFSD,LOG_ERR,
			"Volume %s does not exist on server.\n",volname);
		if (server->num_volumes) {
			fuse_log_for_client(c,AFPFSD,LOG_ERR,"Choose from:\n");
			for (i=0;i<server->num_volumes;i++) 
				fuse_log_for_client(c,AFPFSD,LOG_ERR,"   %s\n",
					server->volumes[i].name);
		}
		goto error;
	}

	if (using_volume->mounted==AFP_VOLUME_MOUNTED) {
		fuse_log_for_client(c,AFPFSD,LOG_ERR,"Volume %s is already mounted\n",volname);
		goto error;
	}

	if (using_volume->flags & HasPassword) {
		bcopy(volpassword,using_volume->volpassword,AFP_VOLPASS_LEN);
		if (strlen(volpassword)<1) {
			fuse_log_for_client(c,AFPFSD,LOG_ERR,"Volume password needed\n");
			goto error;
		}
	}  else bzero(using_volume->volpassword,AFP_VOLPASS_LEN);

	if (volopen(c,using_volume)) {
		fuse_log_for_client(c,AFPFSD,LOG_ERR,"Could not mount volume %s\n",volname);
		goto error;
	}

	if (using_volume->attributes & kSupportsUTF8Names) 
		server->path_encoding=kFPUTF8Name; 
	else 
		server->path_encoding=kFPLongName;

	/* Figure out the name mapping TODO */


	using_volume->server=server;


	return using_volume;
error:
	return NULL;
}


