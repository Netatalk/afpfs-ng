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
#include <stdarg.h>
#include <getopt.h>
#include <signal.h>

#include "afp.h"
#include "dsi.h"
#include "afpfsd.h"
#include "utils.h"
#include "daemon.h"
#include "uams_def.h"
#include "codepage.h"
#include "libafpclient.h"
#include "map_def.h"
#include "fuse_int.h"
#include "fuse_error.h"
#include "fuse_internal.h"

#ifdef __linux
#define FUSE_DEVICE "/dev/fuse"
#else
#define FUSE_DEVICE "/dev/fuse0"
#endif


static int fuse_log_method=LOG_METHOD_SYSLOG;

void trigger_exit(void);

static struct fuse_client * client_base = NULL;

struct afp_volume * global_volume;

static int volopen(struct fuse_client * c, struct afp_volume * volume);
static int process_command(struct fuse_client * c);
static struct afp_volume * attach_volume(struct fuse_client * c,
	struct afp_server * server, char * volname, char * volpassword) ;

void fuse_set_log_method(int new_method)
{
	fuse_log_method=new_method;
}


static int remove_client(struct fuse_client * toremove) 
{
	struct fuse_client * c, * prev=NULL;

	/* Go find the client */
	for (c=client_base;c;c=c->next) {
		if (c==toremove) {
			if (!prev) client_base=NULL;
			else prev->next=toremove->next;
			if (toremove->pending) {
				toremove->toremove=1; /* remove later */
				return 0;
			}
			free(toremove);
			toremove=NULL;
			return 0;
		}
		prev=c;
	}
	return -1;
}

static int continue_client_connection(struct fuse_client * c)
{
	if (c->toremove) {
		c->pending=0;
		remove_client(c);
	}
	add_fd_and_signal(c->fd);
	c->incoming_size=0;
	return 0;
}

static int close_client_connection(struct fuse_client * c)
{
	c->incoming_size=0;
	add_fd_and_signal(c->fd);

	if ((!c) || (c->fd==0)) return -1;
	rm_fd_and_signal(c->fd);
	close(c->fd);
	remove_client(c);
	return 0;
}


static int fuse_add_client(int fd) 
{
	struct fuse_client * c, *newc;

	if ((newc=malloc(sizeof(*newc)))==NULL) goto error;
	memset(newc,0,sizeof(*newc));
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

static int fuse_process_client_fds(fd_set * set, int max_fd, 
	struct fuse_client ** found)
{

	struct fuse_client * c;
	int ret;

	*found=NULL;

	for (c=client_base;c;c=c->next) {
		if (FD_ISSET(c->fd,set)) {
			*found=c;
			ret=process_command(c);
			if (ret<0) return -1;
			return 1;
		}
	}
	return 0;

}

static int fuse_scan_extra_fds(int command_fd, fd_set *set, 
		fd_set * toset, fd_set *exceptfds, int * max_fd)
{

	struct sockaddr_un new_addr;
	socklen_t new_len = sizeof(struct sockaddr_un);
	struct fuse_client * found;


	if (FD_ISSET(command_fd,set)) {
		int new_fd=
			accept(command_fd,
			(struct sockaddr *) &new_addr,&new_len);

		if (new_fd>=0) {
			fuse_add_client(new_fd);
			if ((new_fd+1) > *max_fd) *max_fd=new_fd+1;
		}
		FD_SET(new_fd,toset);
		return 0;
	}

	if ((exceptfds) && (FD_ISSET(command_fd,exceptfds))) {
		printf("We have an exception\n");
		return 0;
	}

	switch (fuse_process_client_fds(set,*max_fd,&found)) {
	case -1: /* we're done with found->fd */
		if (found) {
			FD_CLR(found->fd,toset);
			close(found->fd);
			remove_client(found);
		}
		int i;
		for (i=*max_fd;i>=0;i--)
			if (FD_ISSET(i,set)) {
				*max_fd=i;
				break;
			}

		return -1;
	case 1: /* handled */
		FD_SET(command_fd,toset);
		return 1;
	}
	/* unknown fd */
	sleep(10);

	return -1;
}

static void fuse_log_for_client(void * priv,
	enum loglevels loglevel, int logtype, const char *message) {
	int len = 0;
	struct fuse_client * c = priv;

	if (c) {
		len = strlen(c->outgoing_string);
		snprintf(c->outgoing_string+len,
			MAX_CLIENT_RESPONSE-len,
			message);
	} else {

		if (fuse_log_method & LOG_METHOD_SYSLOG)
			syslog(LOG_INFO, "%s", message);
		if (fuse_log_method & LOG_METHOD_STDOUT)
			printf("%s",message);
	}

}

struct start_fuse_thread_arg {
	struct afp_volume * volume;
	struct fuse_client * client;
	int wait;
	int fuse_result;
	int fuse_errno;
	int changeuid;
};

static void * start_fuse_thread(void * other) 
{
	int fuseargc=0;
	const char *fuseargv[200];
#define mountstring_len (AFP_SERVER_NAME_LEN+1+AFP_VOLUME_NAME_LEN+1)
	char mountstring[mountstring_len];
	struct start_fuse_thread_arg * arg = other;
	struct afp_volume * volume = arg->volume;
	struct fuse_client * c = arg->client;
	struct afp_server * server = volume->server;

	/* Check to see if we have permissions to access the mountpoint */

	snprintf(mountstring,mountstring_len,"%s:%s",
		server->basic.server_name_printable,
			volume->volume_name_printable);
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
	
	if (arg->changeuid) {
		fuseargv[fuseargc]="-o";
		fuseargc++;
		fuseargv[fuseargc]="allow_other";
		fuseargc++;
	}


/* #ifdef USE_SINGLE_THREAD */
	fuseargv[fuseargc]="-s";
	fuseargc++;
/*
#endif
*/
	global_volume=volume; 

	arg->fuse_result= 
		afp_register_fuse(fuseargc, (char **) fuseargv,volume);

	arg->fuse_errno=errno;

	arg->wait=0;
	pthread_cond_signal(&volume->startup_condition_cond);

	log_for_client((void *) c,AFPFSD,LOG_WARNING,
		"Unmounting volume %s from %s\n",
		volume->volume_name_printable,
                volume->mountpoint);

	return NULL;
}

static int volopen(struct fuse_client * c, struct afp_volume * volume)
{
	char mesg[1024];
	unsigned int l = 0;	
	memset(mesg,0,1024);
	int rc=afp_connect_volume(volume,volume->server,mesg,&l,1024);

	log_for_client((void *) c,AFPFSD,LOG_ERR,mesg);

	return rc;

}

static unsigned int send_command(struct fuse_client * c, 
	unsigned int len, const char * data)
{
	char * p = data;
	unsigned int total=0;
	int ret;

	while (total<len) {

		ret = write(c->fd,data,len);
		if (ret<0) {
			perror("Writing");
			return -1;
		}
		total+=ret;
	}
	return total;
}


static unsigned char process_suspend(struct fuse_client * c)
{
	struct afp_server_suspend_request * req =(void *)c->incoming_string;
	struct afp_server * s;

	/* Find the server */
	if ((s=find_server_by_name(req->server_name))==NULL) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}

	if (afp_zzzzz(s)) 
		return AFP_SERVER_RESULT_ERROR;

	loop_disconnect(s);
	
	s->connect_state=SERVER_STATE_DISCONNECTED;
	log_for_client((void *) c,AFPFSD,LOG_NOTICE,
		"Disconnected from %s\n",req->server_name);
	return AFP_SERVER_RESULT_OKAY;
}


static int afp_server_reconnect_loud(struct fuse_client * c, struct afp_server * s) 
{
	char mesg[1024];
	unsigned int l = 2040;
	int rc;

	rc=afp_server_reconnect(s,mesg,&l,l);

	if (rc) 
                log_for_client((void *) c,AFPFSD,LOG_ERR,
                        "%s",mesg);
	return rc;


}


static unsigned char process_resume(struct fuse_client * c)
{
	struct afp_server_resume_request * req =(void *) c->incoming_string;
	struct afp_server * s;

	/* Find the server */
	if ((s=find_server_by_name(req->server_name))==NULL) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}

	if (afp_server_reconnect_loud(c,s)) 
	{
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"Unable to reconnect to %s\n",req->server_name);
		return AFP_SERVER_RESULT_ERROR;
	}
	log_for_client((void *) c,AFPFSD,LOG_NOTICE,
		"Resumed connection to %s\n",req->server_name);

	return AFP_SERVER_RESULT_OKAY;
	
}

static unsigned char process_unmount(struct fuse_client * c)
{
	struct afp_server_unmount_request * req;
	struct afp_server_unmount_response response;
	struct afp_server * s;
	struct afp_volume * v;
	int j=0;

	req=(void *) c->incoming_string;

	/* Try it based on volume name */

	for (s=get_server_base();s;s=s->next) {
		for (j=0;j<s->num_volumes;j++) {
			v=&s->volumes[j];
			if (strcmp(v->volume_name,req->name)==0) {
				goto found;
			}

		}
	}

	/* Try it based on mountpoint name */

	for (s=get_server_base();s;s=s->next) {
		for (j=0;j<s->num_volumes;j++) {
			v=&s->volumes[j];
			if (strcmp(v->mountpoint,req->name)==0) {
				goto found;
			}

		}
	}
	goto notfound;
found:
	if (v->mounted != AFP_VOLUME_MOUNTED ) {
		snprintf(response.unmount_message,1023,
			"%s was not mounted\n",v->mountpoint);
		response.header.result = AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	afp_unmount_volume(v);

	response.header.result = AFP_SERVER_RESULT_OKAY;
	snprintf(response.unmount_message,1023,
		"Unmounted mountpoint %s.\n",v->mountpoint);
	goto done;

notfound:
	response.header.result = AFP_SERVER_RESULT_ERROR;
	snprintf(response.unmount_message,1023,
		"There's no volume or mountpoint called %s.\n",req->name);

done:
	response.header.len=sizeof(struct afp_server_unmount_response);
	send_command(c,response.header.len,(char *) &response);

	close_client_connection(c);

	return 0;

}


static struct afp_volume * find_volume_by_id(volumeid_t * id)
{
	struct afp_server * s;
	struct afp_volume * v;
	 int j;
	for (s=get_server_base();s;s=s->next) {
		for (j=0;j<s->num_volumes;j++) {
			v=&s->volumes[j];
			if (((volumeid_t) v) == *id) 
				return v;
		}
	}
	return NULL;
}


static unsigned char process_detach(struct fuse_client * c)
{
	struct afp_server_detach_request * req;
	struct afp_server_detach_response response;
	struct afp_server * s;
	struct afp_volume * v;
	int j=0;

	req=(void *) c->incoming_string;

	/* Validate the volumeid */

	if ((v = find_volume_by_id(&req->volumeid))==NULL) {
		snprintf(response.detach_message,1023,
			"No such volume to detach");
		response.header.result = AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	if (v->mounted != AFP_VOLUME_MOUNTED ) {
		snprintf(response.detach_message,1023,
			"%s was not attached\n",v->volume_name);
		response.header.result = AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	afp_unmount_volume(v);

	response.header.result = AFP_SERVER_RESULT_OKAY;
	snprintf(response.detach_message,1023,
		"Detached volume %s.\n",v->volume_name);
	goto done;

done:
	response.header.len=sizeof(struct afp_server_detach_response);
	send_command(c,response.header.len,(char *) &response);

	close_client_connection(c);

	return 0;

}

static unsigned char process_ping(struct fuse_client * c)
{
	log_for_client((void *)c,AFPFSD,LOG_INFO,
		"Ping!\n");
	return AFP_SERVER_RESULT_OKAY;
}

static unsigned char process_exit(struct fuse_client * c)
{
	log_for_client((void *)c,AFPFSD,LOG_INFO,
		"Exiting\n");
	trigger_exit();
	return AFP_SERVER_RESULT_OKAY;
}

static unsigned char process_getvolid(struct fuse_client * c)
{
	struct afp_volume * v;
	struct afp_server * s;
	struct afp_server_getvolid_request * req = c->incoming_string;
	struct afp_server_getvolid_response response;
	int ret = AFP_SERVER_RESULT_OKAY;

	if ((c->incoming_size)< sizeof(struct afp_server_getvolid_request)) {
		ret=AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	if ((s=find_server_by_url(&req->url))==NULL) {
		ret=AFP_SERVER_RESULT_NOTCONNECTED;
		goto done;
	}

	if ((v=find_volume_by_url(&req->url))==NULL) {
		ret=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	response.volumeid=(volumeid_t) v;
	response.header.result=AFP_SERVER_RESULT_OKAY;

done:
	response.header.result=ret;
	response.header.len=sizeof(struct afp_server_getvolid_response);

	send_command(c,response.header.len,&response);

	continue_client_connection(c);

	return 0;
}

static unsigned char process_serverinfo(struct fuse_client * c)
{
	struct afp_server_serverinfo_request * req = (void *) c->incoming_string;
	struct afp_server_serverinfo_response response;
	struct afp_server * tmpserver=NULL;

	memset(&response,0,sizeof(response));
	c->pending=1;

	if ((c->incoming_size)< sizeof(struct afp_server_serverinfo_request)) {
		return AFP_SERVER_RESULT_ERROR;
	}

	if ((tmpserver=find_server_by_url(&req->url))) {
		/* We're already connected */
		memcpy(&response.server_basic,
			&tmpserver->basic, sizeof(struct afp_server_basic));
	} else {
		struct sockaddr_in address;
		if ((afp_get_address(NULL,req->url.servername,
			req->url.port,&address))<0) {
			goto error;
		}

		if ((tmpserver=afp_server_init(&address))==NULL) {
			goto error;
		}

		if (afp_server_connect(tmpserver,1)<0) {
			goto error;
		} 
		memcpy(&response.server_basic,
			&tmpserver->basic, sizeof(struct afp_server_basic));
		afp_server_remove(tmpserver);
	}
	response.header.result=AFP_SERVER_RESULT_OKAY;
	goto done;

error:
	response.header.result=AFP_SERVER_RESULT_ERROR;
done:
	response.header.len=sizeof(struct afp_server_serverinfo_response);
printf("Size: %d\n",sizeof(struct afp_server_serverinfo_response));
printf("writing out %d\n",response.header.len);
	send_command(c,response.header.len,&response);

	continue_client_connection(c);

	return 0;

}

static unsigned char process_status(struct fuse_client * c)
{
	struct afp_server * s;

#define STATUS_RESULT_LEN 40960

	char data[STATUS_RESULT_LEN+sizeof(struct afp_server_status_response)];
	unsigned int len=STATUS_RESULT_LEN;
	struct afp_server_status_request * req = c->incoming_string;
	struct afp_server_status_response * response = data;
	char * t = data + sizeof(struct afp_server_status_response);

	memset(data,0,sizeof(data));
	c->pending=1;

	if ((c->incoming_size)< sizeof(struct afp_server_status_request)) 
		return AFP_SERVER_RESULT_ERROR;

	afp_status_header(t,&len);

/*
	log_for_client((void *)c,AFPFSD,LOG_INFO,text);
*/

	s=get_server_base();

	for (s=get_server_base();s;s=s->next) {
		afp_status_server(s,t,&len);
/*
		log_for_client((void *)c,AFPFSD,LOG_DEBUG,text);
*/

	}

	response->header.len=sizeof(struct afp_server_status_response)+
		(STATUS_RESULT_LEN-len);
	response->header.result=AFP_SERVER_RESULT_OKAY;

	send_command(c,response->header.len,data);

	close_client_connection(c);

	return 0;

}

static unsigned char process_getvols(struct fuse_client * c)
{

	struct afp_server_getvols_request * request = c->incoming_string;
	struct afp_server_getvols_response * response;
	struct afp_server * server;
	struct afp_volume * volume;
	unsigned int maximum_that_will_fit;
	unsigned int result;
	unsigned int numvols;
	int i;
	char * p;
	unsigned int len = sizeof(struct afp_server_getvols_response);
	struct afp_volume_summary * sum;

	if (((c->incoming_size)< sizeof(struct afp_server_getvols_request)) ||
		(request->start<0)) {
		result=AFP_SERVER_RESULT_ERROR;
		goto error;
	}

	if ((server=find_server_by_url(&request->url))==NULL) {
		result=AFP_SERVER_RESULT_NOTCONNECTED;
		goto error;
	}

	maximum_that_will_fit = 
		(MAX_CLIENT_RESPONSE - sizeof(struct afp_server_getvols_response)) /
		sizeof(struct afp_volume_summary);

	/* find out how many there are */

	numvols = server->num_volumes;

	if (request->count<numvols) 
		numvols=request->count;

	if (request->start>numvols) 
		goto error;

	
	len += numvols * sizeof(struct afp_volume_summary);;

	response = malloc(len);

	p = (void *) response + sizeof(struct afp_server_getvols_response);

	for (i=request->start;i<request->start + numvols;i++) {
		volume = &server->volumes[i];
		sum=p;
		memcpy(sum->volume_name,volume->volume_name,AFP_VOLUME_NAME_LEN);
		sum->flags=volume->flags;
	
		p=p + sizeof(struct afp_volume_summary);
	}

	response->num=numvols;

	result = AFP_SERVER_RESULT_OKAY;

	goto done;


error:
	response = (void*) malloc(len);

done:
	response->header.len=len;
	response->header.result=result;

	send_command(c,response->header.len,(char *)response);

	free(response);

	continue_client_connection(c);

	return 0;
}

static unsigned char process_open(struct fuse_client * c)
{
	struct afp_server_open_response response;
	struct afp_server_open_request * request = c->incoming_string;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;
	struct afp_file_info * fp;

	if ((c->incoming_size)< sizeof(struct afp_server_open_request)) {
		result=AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	/* Find the volume */
	if ((v = find_volume_by_id(&request->volumeid))==NULL) {
		result=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	ret = afp_ml_open(v,request->path,request->mode, &fp);

	if (ret) {
		result=ret;
		free(fp);
		goto done;
	}
	response.fileid=fp->forkid;

	free(fp);

done:
	response.header.len=sizeof(struct afp_server_open_response);
	response.header.result=result;
	send_command(c,response.header.len,(char*) &response);

	continue_client_connection(c);

	return 0;
}

static unsigned char process_read(struct fuse_client * c)
{
	struct afp_server_read_response * response;
	struct afp_server_read_request * request = c->incoming_string;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;
	char * data;
	unsigned int eof = 0;
	unsigned int received;
	unsigned int len = sizeof(struct afp_server_read_response);

	if ((c->incoming_size)< sizeof(struct afp_server_read_request)) {
		response=malloc(len);
		result=AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	/* Find the volume */
	if ((v = find_volume_by_id(&request->volumeid))==NULL) {
		response=malloc(len);
		result=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	len+=request->length;
	response = malloc(len);
	data = ((char *) response) + sizeof(struct afp_server_read_response);

	ret = ll_read(v,data,request->length,request->start,
		request->fileid,&eof);

	if (ret>0) {
		received=ret;
	}


done:
	response->eof=eof;
	response->header.len=len;
	response->header.result=result;
	response->received=received;
	send_command(c,len,(char*) response);

	continue_client_connection(c);

	return 0;
}

static unsigned char process_close(struct fuse_client * c)
{
	struct afp_server_close_response response;
	struct afp_server_close_request * request = c->incoming_string;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;

	if ((c->incoming_size)< sizeof(struct afp_server_close_request)) {
		result=AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	/* Find the volume */
	if ((v = find_volume_by_id(&request->volumeid))==NULL) {
		result=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	ret = afp_closefork(v,request->fileid);

done:
	response.header.len=sizeof(struct afp_server_close_response);
	response.header.result=ret;
	send_command(c,response.header.len,(char*) &response);

	continue_client_connection(c);

	return 0;
}

static unsigned char process_stat(struct fuse_client * c)
{
	struct afp_server_stat_response response;
	struct afp_server_stat_request * request = c->incoming_string;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;

	if ((c->incoming_size)< sizeof(struct afp_server_stat_request)) {
		result=AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	/* Find the volume */
	if ((v = find_volume_by_id(&request->volumeid))==NULL) {
		result=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	ret = afp_ml_getattr(v,request->path,&response.stat);

	if (ret==-ENOENT) ret=AFP_SERVER_RESULT_ENOENT;

done:
	response.header.len=sizeof(struct afp_server_stat_response);
	response.header.result=ret;
	send_command(c,response.header.len,(char*) &response);

	continue_client_connection(c);

	return 0;
}

static unsigned char process_readdir(struct fuse_client * c)
{
	struct afp_server_readdir_request * req = c->incoming_string;
	struct afp_server_readdir_response * response;
	unsigned int len = sizeof(struct afp_server_readdir_response);
	unsigned int result;
	struct afp_volume * v;
	char * data, * p;
	struct afp_file_info *filebase, *fp;
	unsigned int numfiles=0;
	int i;
	unsigned int maximum_that_will_fit;
	int ret;

	if (((c->incoming_size)< sizeof(struct afp_server_readdir_request)) ||
		(req->start<0)) {
		result=AFP_SERVER_RESULT_ERROR;
		goto error;
	}

	/* Find the volume */
	if ((v = find_volume_by_id(&req->volumeid))==NULL) {
		result=AFP_SERVER_RESULT_ENOENT;
		goto error;
	}

	/* Get the file list */

	ret=afp_ml_readdir(v,req->path,&filebase);
	if (ret) goto error;

	/* Count how many we have */
	for (fp=filebase;fp;fp=fp->next) numfiles++;

	/* Make sure we're not running off the end */
	if (req->start > numfiles) goto error;

	/* Make sure we don't respond with more than asked */
	if (numfiles>req->count)
		numfiles=req->count;

	/* Figure out the maximum that could fit in our transmit buffer */

	maximum_that_will_fit = 
		(MAX_CLIENT_RESPONSE - sizeof(struct afp_server_readdir_response)) /
		(sizeof(struct afp_file_info_basic));

	if (maximum_that_will_fit<numfiles)
		numfiles=maximum_that_will_fit;

	len+=numfiles*sizeof(struct afp_file_info_basic);
	response = (void *) 
		malloc(len + sizeof(struct afp_server_readdir_response));
	result=AFP_SERVER_RESULT_OKAY;
	data=(void *) response+sizeof(struct afp_server_readdir_response);

	fp=filebase;
	/* Advance to the first one */
	for (i=0;i<req->start;i++) {
		if (!fp) {
			response->eod=1;
			response->numfiles=0;
			afp_ml_filebase_free(&filebase);
			goto done;
		}
		fp=fp->next;
	}

	/* Make a copy */
	p=data;
	for (i=0;i<numfiles;i++) {
		memcpy(p,&fp->basic,sizeof(struct afp_file_info_basic));
		fp=fp->next;
		if (!fp) {
			response->eod=1;
			i++;
			break;
		}
		p+=sizeof(struct afp_file_info_basic);
	}

	response->numfiles=i;

	afp_ml_filebase_free(&filebase);


	goto done;

error:
	response = (void*) malloc(len);
	result=AFP_SERVER_RESULT_ERROR;
	response->numfiles=0;

done:
	response->header.len=len;
	response->header.result=result;

	send_command(c,response->header.len,(char *)response);

	continue_client_connection(c);

	return 0;

}

static int process_connect(struct fuse_client * c)
{
	struct afp_server_connect_request * req;
	struct afp_server  * s=NULL;
	struct afp_volume * volume;
	struct afp_connection_request conn_req;
	int response_len;
	struct afp_server_connect_response * response;
	char * r;
	int ret;
	struct stat lstat;
	int response_result;
	int error=0;

	if ((c->incoming_size) < sizeof(struct afp_server_connect_request)) 
		goto error;

	req=(void *) c->incoming_string;

	log_for_client((void *)c,AFPFSD,LOG_NOTICE,
		"Connecting to volume %s and server %s\n",
		(char *) req->url.volumename,
		(char *) req->url.servername);

	if ((s=find_server_by_url(&req->url))) {
printf("Already connected\n");
		response_result=AFP_SERVER_RESULT_ALREADY_CONNECTED;
           	goto done;
        }


	if ((afp_default_connection_request(&conn_req,&req->url))==-1) {
		log_for_client((void *)c,AFPFSD,LOG_ERR,
			"Unknown UAM");
		return -1;
	}

	conn_req.uam_mask=req->uam_mask;

/* 
* Sets connect_error:  
* 0:
*      No error
* -ENONET: 
*      could not get the address of the server
* -ENOMEM: 
*      could not allocate memory
* -ETIMEDOUT: 
*      timed out waiting for connection
* -ENETUNREACH:
*      Server unreachable
* -EISCONN:
*      Connection already established
* -ECONNREFUSED:
*     Remote server has refused the connection
* -EACCES, -EPERM, -EADDRINUSE, -EAFNOSUPPORT, -EAGAIN, -EALREADY, -EBADF,
* -EFAULT, -EINPROGRESS, -EINTR, -ENOTSOCK, -EINVAL, -EMFILE, -ENFILE, 
* -ENOBUFS, -EPROTONOSUPPORT:
*     Internal error
*
* Returns:
* 0: No error
* -1: An error occurred
*/




	if ((s=afp_server_full_connect(c,&conn_req,&error))==NULL) {
		signal_main_thread();
		goto error;
	}

	response_result=AFP_SERVER_RESULT_OKAY;
	ret=0;
	goto done;

error:
	afp_server_remove(s);
	response_result=AFP_SERVER_RESULT_ERROR;
	ret=-1;

done:
	response_len = sizeof(struct afp_server_connect_response) + 
		client_string_len(c);
	response = malloc(response_len);
	r=response;
	memset(response,0,response_len);

	if (s) 
		memcpy(response->loginmesg,s->loginmesg,AFP_LOGINMESG_LEN);

	response->header.result=response_result;
	response->header.len=response_len;
	response->connect_error=error;
	memset(&response->serverid,0,sizeof(serverid_t));
	memcpy(&response->serverid,&s,sizeof(s));
	r=((char *) response) +sizeof(struct afp_server_connect_response);
	memcpy(r,c->outgoing_string,client_string_len(c));

	send_command(c,response_len,response);

	free(response);

	if (ret) close_client_connection(c); else
		continue_client_connection(c);

	return ret;

}


static int process_mount(struct fuse_client * c)
{
	struct afp_server_mount_request * req;
	struct afp_server  * s=NULL;
	struct afp_volume * volume;
	struct afp_connection_request conn_req;
	int ret;
	struct stat lstat;
	unsigned int response_len;
	int response_result;
	char * r;
	struct afp_server_mount_response * response;


	if ((c->incoming_size) < sizeof(struct afp_server_mount_request)) 
		goto error;

	req=(void *) c->incoming_string;

	if ((ret=access(req->mountpoint,X_OK))!=0) {
		log_for_client((void *)c,AFPFSD,LOG_DEBUG,
			"Incorrect permissions on mountpoint %s: %s\n",
			req->mountpoint, strerror(errno));

		goto error;
	}

	if (stat(FUSE_DEVICE,&lstat)) {
		printf("Could not find %s\n",FUSE_DEVICE);
		goto error;
	}

	if (access(FUSE_DEVICE,R_OK | W_OK )!=0) {
		log_for_client((void *)c, AFPFSD,LOG_NOTICE, 
			"Incorrect permissions on %s, mode of device"
			" is %o, uid/gid is %d/%d.  But your effective "
			"uid/gid is %d/%d\n", 
				FUSE_DEVICE,lstat.st_mode, lstat.st_uid, 
				lstat.st_gid, 
				geteuid(),getegid());
		goto error;
	}

	log_for_client((void *)c,AFPFSD,LOG_NOTICE,
		"Mounting %s from %s on %s\n",
		(char *) req->url.servername, 
		(char *) req->url.volumename,req->mountpoint);

	if ((s=find_server_by_url(&req->url))==NULL) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->url.servername);
		return AFP_SERVER_RESULT_ERROR;
	}

	if ((volume=attach_volume(c,s,req->url.volumename,
		req->url.volpassword))==NULL) {
		goto error;
	}

	volume->extra_flags|=req->volume_options;

	volume->mapping=req->map;
	afp_detect_mapping(volume);

	snprintf(volume->mountpoint,255,req->mountpoint);

	/* Create the new thread and block until we get an answer back */
	{
		pthread_mutex_t mutex;
		struct timespec ts;
		struct timeval tv;
		int ret;
		struct start_fuse_thread_arg arg;
		memset(&arg,0,sizeof(arg));
		arg.client = c;
		arg.volume = volume;
		arg.wait = 1;
		arg.changeuid=req->changeuid;

		gettimeofday(&tv,NULL);
		ts.tv_sec=tv.tv_sec;
		ts.tv_sec+=5;
		ts.tv_nsec=tv.tv_usec*1000;
		pthread_mutex_init(&mutex,NULL);
		pthread_cond_init(&volume->startup_condition_cond,NULL);

		/* Kickoff a thread to see how quickly it exits.  If
		 * it exits quickly, we have an error and it failed. */

		pthread_create(&volume->thread,NULL,start_fuse_thread,&arg);

		if (arg.wait) ret = pthread_cond_timedwait(
				&volume->startup_condition_cond,&mutex,&ts);

		report_fuse_errors(c);
		
		switch (arg.fuse_result) {
		case 0:
		if (volume->mounted==AFP_VOLUME_UNMOUNTED) {
			/* Try and discover why */
			switch(arg.fuse_errno) {
			case ENOENT:
				log_for_client((void *)c,AFPFSD,LOG_ERR,
					"Permission denied, maybe a problem with the fuse device or mountpoint?\n");
				break;
			default:
				log_for_client((void *)c,AFPFSD,LOG_ERR,
					"Mounting of volume %s of server %s failed.\n", 
					volume->volume_name_printable, 
					volume->server->basic.server_name_printable);
			}
			goto error;
		} else {
			log_for_client((void *)c,AFPFSD,LOG_NOTICE,
				"Mounting of volume %s of server %s succeeded.\n", 
					volume->volume_name_printable, 
					volume->server->basic.server_name_printable);
			goto done;
		}
		break;
		case ETIMEDOUT:
			log_for_client((void *)c,AFPFSD,LOG_NOTICE,
				"Still trying.\n");
			goto error;
			break;
		default:
			volume->mounted=AFP_VOLUME_UNMOUNTED;
			log_for_client((void *)c,AFPFSD,LOG_NOTICE,
				"Unknown error %d, %d.\n", 
				arg.fuse_result,arg.fuse_errno);
			goto error;
		}

	}

	response_result=AFP_SERVER_RESULT_OKAY;
	goto done;
error:
	if ((s) && (!something_is_mounted(s))) {
		afp_server_remove(s);
	}
	response_result=AFP_SERVER_RESULT_ERROR;

done:
	signal_main_thread();

	response_len = sizeof(struct afp_server_mount_response) + 
		client_string_len(c);
	r = malloc(response_len);
	response = (void *) r;
	response->header.result=response_result;
	response->header.len=response_len;
	if (volume) response->volumeid=volume->volid;
	r=((char *)response)+sizeof(struct afp_server_mount_response);
	memcpy(r,c->outgoing_string,client_string_len(c));

	send_command(c,response_len,response);

	free(response);
}


	
static int process_attach(struct fuse_client * c)
{
	struct afp_server_attach_request * req;
	struct afp_server  * s=NULL;
	struct afp_volume * volume = NULL;
	struct afp_connection_request conn_req;
	int ret;
	struct stat lstat;
	unsigned int response_len;
	int response_result;
	char * r;
	struct afp_server_attach_response * response;

	if ((c->incoming_size) < sizeof(struct afp_server_attach_request)) 
		goto error;

	req=(void *) c->incoming_string;

	log_for_client((void *)c,AFPFSD,LOG_NOTICE,
		"Attaching volume %s on server %s\n",
		(char *) req->url.servername, 
		(char *) req->url.volumename);

	if ((s=find_server_by_url(&req->url))==NULL) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"Not yet connected to server %s\n",req->url.servername);
		goto error;
	}

	if ((volume=find_volume_by_url(&req->url))) {
		response_result=AFP_SERVER_RESULT_ALREADY_ATTACHED;
printf("Already attached\n");
		goto done;
	}

	if ((volume=attach_volume(c,s,req->url.volumename,
		req->url.volpassword))==NULL) {
		goto error;
	}

	volume->extra_flags|=req->volume_options;

	volume->mapping=AFP_MAPPING_UNKNOWN;

	response_result=AFP_SERVER_RESULT_OKAY;
	goto done;
error:
	if ((s) && (!something_is_mounted(s))) {
		afp_server_remove(s);
	}
	response_result=AFP_SERVER_RESULT_ERROR;

done:
	signal_main_thread();

	response_len = sizeof(struct afp_server_attach_response) + 
		client_string_len(c);
	r = malloc(response_len);
	memset(r,0,response_len);
	response = (void *) r;
	response->header.result=response_result;
	response->header.len=response_len;
	if (volume) 
		response->volumeid=(volumeid_t) volume;

	r=((char *)response)+sizeof(struct afp_server_attach_response);
	memcpy(r,c->outgoing_string,client_string_len(c));

	send_command(c,response_len,response);

	free(response);

	continue_client_connection(c);
}

static void * process_command_thread(void * other)
{

	struct fuse_client * c = other;
	int ret=0;
	char tosend[sizeof(struct afp_server_response_header) 
		+ MAX_CLIENT_RESPONSE];
	struct afp_server_request_header * req = c->incoming_string;
	struct afp_server_response_header response;

	switch(req->command) {
	case AFP_SERVER_COMMAND_SERVERINFO: 
		ret=process_serverinfo(c);
		break;
	case AFP_SERVER_COMMAND_CONNECT: 
		ret=process_connect(c);
		break;
	case AFP_SERVER_COMMAND_MOUNT: 
		ret=process_mount(c);
		break;
	case AFP_SERVER_COMMAND_ATTACH: 
		ret=process_attach(c);
		break;
	case AFP_SERVER_COMMAND_DETACH: 
		ret=process_detach(c);
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
	case AFP_SERVER_COMMAND_PING: 
		ret=process_ping(c);
		break;
	case AFP_SERVER_COMMAND_GETVOLID: 
		ret=process_getvolid(c);
		break;
	case AFP_SERVER_COMMAND_READDIR: 
		ret=process_readdir(c);
		break;
	case AFP_SERVER_COMMAND_GETVOLS: 
		ret=process_getvols(c);
		break;
	case AFP_SERVER_COMMAND_STAT: 
		ret=process_stat(c);
		break;
	case AFP_SERVER_COMMAND_OPEN: 
		ret=process_open(c);
		break;
	case AFP_SERVER_COMMAND_READ: 
		ret=process_read(c);
		break;
	case AFP_SERVER_COMMAND_CLOSE: 
		ret=process_close(c);
		break;
	case AFP_SERVER_COMMAND_EXIT: 
		ret=process_exit(c);
		break;
	default:
		log_for_client((void *)c,AFPFSD,LOG_ERR,"Unknown command\n");
	}

	return NULL;

}
static int process_command(struct fuse_client * c)
{
	int ret;
	int fd;
	unsigned int offset = 0;
	struct afp_server_request_header * header;

	if (c->incoming_size==0) {
		ret=read(c->fd,&c->incoming_string,
			sizeof(struct afp_server_request_header));
		if ((ret<0) || (ret<sizeof(struct afp_server_request_header))) {
			perror("reading command 1");
			return -1;
		}
		c->incoming_size+=ret;
		return 0;
	}

	header = (struct afp_server_request_header *) c->incoming_string;

	if (c->incoming_size<header->len) {
		ret=read(c->fd,
			((char *)&c->incoming_string) + c->incoming_size,
			AFP_CLIENT_INCOMING_BUF - c->incoming_size);
		if (ret<=0) {
			perror("reading command 2");
			return -1;
		}
		c->incoming_size+=ret;
	}

	if (c->incoming_size<header->len) 
		return 0;

	/* Okay, so we have a full one.  Don't read anything until we've 
	   processed it. */

	rm_fd_and_signal(c->fd);

	pthread_t thread;
	pthread_create(&thread,NULL,process_command_thread,c);
	return 0;
out:
#if 0
	fd=c->fd;
	c->fd=0;
	remove_client(c);
	close(fd);
	rm_fd_and_signal(fd);
#endif
	return 0;
}


static struct afp_volume * attach_volume(struct fuse_client * c,
	struct afp_server * server, char * volname, char * volpassword) 
{
	struct afp_volume * using_volume;

	using_volume = find_volume_by_name(server,volname);

	if (!using_volume) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"Volume %s does not exist on server %s.\n",volname,
			server->basic.server_name_printable);
		if (server->num_volumes) {
			char names[1024];
			afp_list_volnames(server,names,1024);
			log_for_client((void *)c,AFPFSD,LOG_ERR,
				"Choose from: %s\n",names);
		}
		goto error;
	}

	if (using_volume->mounted==AFP_VOLUME_MOUNTED) {
		log_for_client((void *)c,AFPFSD,LOG_ERR,
			"Volume %s is already mounted on %s\n",volname,
			using_volume->mountpoint);
		goto error;
	}

	if (using_volume->flags & HasPassword) {
		bcopy(volpassword,using_volume->volpassword,AFP_VOLPASS_LEN);
		if (strlen(volpassword)<1) {
			log_for_client((void *) c,AFPFSD,LOG_ERR,"Volume password needed\n");
			goto error;
		}
	}  else memset(using_volume->volpassword,0,AFP_VOLPASS_LEN);

	using_volume->server=server;

	if (volopen(c,using_volume)) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,"Could not mount volume %s\n",volname);
		goto error;
	}


	return using_volume;
error:
	return NULL;
}


static struct libafpclient client = {
	.unmount_volume = fuse_unmount_volume,
	.log_for_client = fuse_log_for_client,
	.forced_ending_hook =fuse_forced_ending_hook,
	.scan_extra_fds = fuse_scan_extra_fds};

int fuse_register_afpclient(void)
{
	libafpclient_register(&client);
	return 0;
}



