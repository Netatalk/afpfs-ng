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

#include "config.h"
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
#include "daemon_client.h"
#include "commands.h"

#define client_string_len(x) \
	(strlen(((struct daemon_client *)(x))->outgoing_string))


void trigger_exit(void);  /* move this */

static int volopen(struct daemon_client * c, struct afp_volume * volume)
{
	char mesg[1024];
	unsigned int l = 0;	
	memset(mesg,0,1024);
	int rc=afp_connect_volume(volume,volume->server,mesg,&l,1024);

	log_for_client((void *) c,AFPFSD,LOG_ERR,mesg);

	return rc;

}

static unsigned char process_suspend(struct daemon_client * c)
{
	struct afp_server_suspend_request * req =(void *)c->complete_packet;
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


static int afp_server_reconnect_loud(struct daemon_client * c, struct afp_server * s) 
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


static unsigned char process_resume(struct daemon_client * c)
{
	struct afp_server_resume_request * req =(void *) c->complete_packet;
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

/* process_unmount
 *
 * result returns:
 * AFP_SERVER_RESULT_NOTATTACHED
 * AFP_SERVER_RESULT_NOVOLUME
 * AFP_SERVER_RESULT_OKAY
 */

static unsigned char process_unmount(struct daemon_client * c)
{
	struct afp_server_unmount_request * req;
	struct afp_server_unmount_response response;
	struct afp_server * s;
	struct afp_volume * v;
	int j=0;

	req=(void *) c->complete_packet;

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
	response.header.result = AFP_SERVER_RESULT_NOVOLUME;
	goto notfound;
found:
	if (v->mounted != AFP_VOLUME_MOUNTED ) {
		snprintf(response.unmount_message,1023,
			"%s was not mounted\n",v->mountpoint);
		response.header.result = AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	afp_unmount_volume(v);

	response.header.result = AFP_SERVER_RESULT_OKAY;
	snprintf(response.unmount_message,1023,
		"Unmounted mountpoint %s.\n",v->mountpoint);
	goto done;

notfound:
	snprintf(response.unmount_message,1023,
		"There's no volume or mountpoint called %s.\n",req->name);

done:
	response.header.len=sizeof(struct afp_server_unmount_response);
	send_command(c,response.header.len,(char *) &response);

	remove_command(c);

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

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


static unsigned char process_detach(struct daemon_client * c)
{
	struct afp_server_detach_request * req;
	struct afp_server_detach_response response;
	struct afp_server * s;
	struct afp_volume * v;
	int j=0;

	req=(void *) c->complete_packet;

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

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;

}

static unsigned char process_ping(struct daemon_client * c)
{
	log_for_client((void *)c,AFPFSD,LOG_INFO,
		"Ping!\n");
	return AFP_SERVER_RESULT_OKAY;
}

static unsigned char process_exit(struct daemon_client * c)
{
	log_for_client((void *)c,AFPFSD,LOG_INFO,
		"Exiting\n");
	trigger_exit();
	return AFP_SERVER_RESULT_OKAY;
}

/* process_get_mountpoint()
 *
 */

static unsigned char process_get_mountpoint(struct daemon_client * c)
{
	struct afp_volume * v;
	struct afp_server_get_mountpoint_request * req = 
		(void *) c->complete_packet;
	struct afp_server_get_mountpoint_response response;
	int ret = AFP_SERVER_RESULT_OKAY;

	if ((c->completed_packet_size)< 
		sizeof(struct afp_server_get_mountpoint_request)) {
		ret=AFP_SERVER_RESULT_ERROR;
		goto done;
	}
	if ((v=find_volume_by_url(&req->url))==NULL) {
		ret=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	memcpy(response.mountpoint,v->mountpoint,PATH_MAX);
	ret=AFP_SERVER_RESULT_OKAY;

done:
	response.header.result=ret;
	response.header.len=sizeof(struct afp_server_get_mountpoint_response);

	send_command(c,response.header.len,(char *) &response);

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;
}

/* process_getvolid()
 *
 * Gets the volume id for a url provided, if it exists
 *
 * Sets the return result to be:
 * AFP_SERVER_RESULT_ERROR : internal error
 * AFP_SERVER_RESULT_NOTCONNECTED: not logged in
 * AFP_SERVER_RESULT_NOTATTACHED: connected, but not attached to volume
 * AFP_SERVER_RESULT_OKAY: lookup succeeded, volumeid set 
 */

static unsigned char process_getvolid(struct daemon_client * c)
{
	struct afp_volume * v;
	struct afp_server * s;
	struct afp_server_getvolid_request * req = (void *) c->complete_packet;
	struct afp_server_getvolid_response response;
	int ret = AFP_SERVER_RESULT_OKAY;

	if ((c->completed_packet_size)< sizeof(struct afp_server_getvolid_request)) {
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

	send_command(c,response.header.len,(char *) &response);

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;
}

static unsigned char process_serverinfo(struct daemon_client * c)
{
	struct afp_server_serverinfo_request * req = (void *) c->complete_packet;
	struct afp_server_serverinfo_response response;
	struct afp_server * tmpserver=NULL;

	memset(&response,0,sizeof(response));
	c->pending=1;

	if ((c->completed_packet_size)< sizeof(struct afp_server_serverinfo_request)) {
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
	send_command(c,response.header.len,(char *) &response);

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;

}

static unsigned char process_status(struct daemon_client * c)
{
	struct afp_server * s;

#define STATUS_RESULT_LEN 40960

	char data[STATUS_RESULT_LEN+sizeof(struct afp_server_status_response)];
	unsigned int len=STATUS_RESULT_LEN;
	struct afp_server_status_request * req = (void *) c->complete_packet;
	struct afp_server_status_response * response = (void *) data;
	char * t = data + sizeof(struct afp_server_status_response);

	memset(data,0,sizeof(data));
	c->pending=1;

	if ((c->completed_packet_size)< sizeof(struct afp_server_status_request)) 
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

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;

}

static unsigned char process_getvols(struct daemon_client * c)
{

	struct afp_server_getvols_request * request = (void *) c->complete_packet;
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

	if (((c->completed_packet_size)< sizeof(struct afp_server_getvols_request)) ||
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
		sum=(void *) p;
		memcpy(sum->volume_name_printable,
			volume->volume_name_printable,AFP_VOLUME_NAME_UTF8_LEN);
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

	if (request->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;
}

static unsigned char process_open(struct daemon_client * c)
{
	struct afp_server_open_response response;
	struct afp_server_open_request * request = (void *) c->complete_packet;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;
	struct afp_file_info * fp;

	if ((c->completed_packet_size)< sizeof(struct afp_server_open_request)) {
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

	if (request->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;
}

static unsigned char process_read(struct daemon_client * c)
{
	struct afp_server_read_response * response;
	struct afp_server_read_request * request = (void *) c->complete_packet;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;
	char * data;
	unsigned int eof = 0;
	unsigned int received;
	unsigned int len = sizeof(struct afp_server_read_response);

	if ((c->completed_packet_size)< sizeof(struct afp_server_read_request)) {
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

	if (request->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;
}

static unsigned char process_close(struct daemon_client * c)
{
	struct afp_server_close_response response;
	struct afp_server_close_request * request = (void *) c->complete_packet;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;

	if ((c->completed_packet_size)< sizeof(struct afp_server_close_request)) {
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

	if (request->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;
}

static unsigned char process_stat(struct daemon_client * c)
{
	struct afp_server_stat_response response;
	struct afp_server_stat_request * request = (void *) c->complete_packet;
	struct afp_volume * v;
	int ret;
	int result = AFP_SERVER_RESULT_OKAY;

	if ((c->completed_packet_size)< sizeof(struct afp_server_stat_request)) {
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

	if (request->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;
}

static unsigned char process_readdir(struct daemon_client * c)
{
	struct afp_server_readdir_request * req = (void *) c->complete_packet;
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

	if (((c->completed_packet_size)< sizeof(struct afp_server_readdir_request)) ||
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

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);

	return 0;

}

static int process_connect(struct daemon_client * c)
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

	if ((c->completed_packet_size) < sizeof(struct afp_server_connect_request)) 
		return -1;

	req=(void *) c->complete_packet;

	log_for_client((void *)c,AFPFSD,LOG_NOTICE,
		"Connecting to volume %s and server %s\n",
		(char *) req->url.volumename,
		(char *) req->url.servername);

	if ((s=find_server_by_url(&req->url))) {
		response_result=AFP_SERVER_RESULT_ALREADY_CONNECTED;
           	goto done;
        }

	if ((afp_default_connection_request(&conn_req,&req->url))==-1) {
		log_for_client((void *)c,AFPFSD,LOG_ERR,
			"Unknown UAM");
		goto error;
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
	r=(char *) response;
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

	send_command(c,response_len,(char *) response);

	free(response);

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);


	return ret;

}

/* process_mount() 
 *
 * Does a mount
 *
 * Returns:
 *
 * Sends back response_result, one of:
 * AFP_SERVER_RESULT_OKAY
 * AFP_SERVER_RESULT_MOUNTPOINT_PERM
 * AFP_SERVER_RESULT_MOUNTPOINT_NOEXIST
 * AFP_SERVER_RESULT_NOSERVER
 * AFP_SERVER_RESULT_NOVOLUME:
 * AFP_SERVER_RESULT_ALREADY_MOUNTED:
 * AFP_SERVER_RESULT_VOLPASS_NEEDED:
 * AFP_SERVER_RESULT_ERROR_UNKNOWN:
 * AFP_SERVER_RESULT_TIMEDOUT:
*/


static int process_mount(struct daemon_client * c)
{
	struct afp_server_mount_request * req;
	struct afp_connection_request conn_req;
	unsigned int response_len;
	int response_result = AFP_SERVER_RESULT_OKAY;
	char * r;
	volumeid_t volumeid;
	
	memset(&volumeid,0,sizeof(volumeid));

	if ((c->completed_packet_size) < sizeof(struct afp_server_mount_request)) 
		goto error;

#ifdef HAVE_LIBFUSE
	response_result=fuse_mount(c, &volumeid);
#else
	response_result=AFP_SERVER_RESULT_NOTSUPPORTED;

#endif

	response_result=AFP_SERVER_RESULT_OKAY;
	goto done;
error:
#if 0
	if ((s) && (!something_is_mounted(s))) {
		afp_server_remove(s);
	}
#endif

done:
	signal_main_thread();

	struct afp_server_mount_response * response;
	response_len = sizeof(struct afp_server_mount_response) + 
		client_string_len(c);

	response = malloc(response_len);
	memset(response,0,response_len);
	response->header.result=response_result;
	response->header.len=response_len;
	response->volumeid=volumeid;
	r=((char *)response)+sizeof(struct afp_server_mount_response);
	memcpy(r,c->outgoing_string,client_string_len(c));
	send_command(c,response_len,(char *) response);


	free(response);

	close_client_connection(c);

#if 0
	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);
#endif
}


	
static int process_attach(struct daemon_client * c)
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

	if ((c->completed_packet_size) < sizeof(struct afp_server_attach_request)) 
		goto error;

	req=(void *) c->complete_packet;

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
		goto done;
	}

	if ((volume=command_sub_attach_volume(c,s,req->url.volumename,
		req->url.volpassword,NULL))==NULL) {
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

	send_command(c,response_len,(char *) response);

	free(response);

	if (req->header.close) 
		close_client_connection(c);
	else
		continue_client_connection(c);
}


static void * process_command_thread(void * other)
{

	struct daemon_client * c = other;
	int ret=0;
	char tosend[sizeof(struct afp_server_response_header) 
		+ MAX_CLIENT_RESPONSE];
	struct afp_server_request_header * req = (void *) c->complete_packet;
	struct afp_server_response_header response;
printf("******* processing command %d\n",req->command);

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
	case AFP_SERVER_COMMAND_GET_MOUNTPOINT: 
		ret=process_get_mountpoint(c);
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
	/* Shift back */

	remove_command(c);
	
	return NULL;


}

int process_command(struct daemon_client * c)
{
	int ret;
	int fd;
	unsigned int offset = 0;
	struct afp_server_request_header * header;
	pthread_attr_t        attr;  /* for pthread_create */

	if (c->incoming_size==0) {

		/* We're at the start of the packet */

		c->a=&c->incoming_string;

		ret=read(c->fd,c->incoming_string,
			sizeof(struct afp_server_request_header));
		if (ret==0) {
			printf("Done reading\n");
			return -1;
		}
		if (ret<0) {
			perror("error reading command");
			return -1;
		}

		c->incoming_size+=ret;
		c->a+=ret;

		if (ret<sizeof(struct afp_server_request_header)) {
			/* incomplete header, continue to read */
exit(0);
			return 2;
		}

		header = (struct afp_server_request_header *) &c->incoming_string;


		if (c->incoming_size==header->len) goto havefullone;

		/* incomplete header, continue to read */
		return 2;
	}

	/* Okay, we're continuing to read */
	header = (struct afp_server_request_header *) &c->incoming_string;

	ret=read(c->fd, c->a,
		AFP_CLIENT_INCOMING_BUF - c->incoming_size);
	if (ret<=0) {
		perror("reading command 2");
		return -1;
	}
	c->a+=ret;
	c->incoming_size+=ret;

	if (c->incoming_size<header->len) 
		return 0;

havefullone:
	/* Okay, so we have a full one.  Copy the buffer. */

	header = (struct afp_server_request_header *) &c->incoming_string;

	/* do the copy */
	c->completed_packet_size=header->len;
	memcpy(c->complete_packet,c->incoming_string,c->completed_packet_size);

	/* shift things back */
	c->a-=c->completed_packet_size;
	memmove(c->incoming_string,c->incoming_string+c->completed_packet_size,
		c->completed_packet_size);

	memset(c->incoming_string+c->completed_packet_size,0,
		AFP_CLIENT_INCOMING_BUF-c->completed_packet_size);
	c->incoming_size-=c->completed_packet_size;;

	rm_fd_and_signal(c->fd);


	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&c->processing_thread,&attr,
		process_command_thread,c)<0) {
		perror("pthread_create");
		return -1;
	}
	return 0;
out:
	fd=c->fd;
	c->fd=0;
	remove_client(&c);
	close(fd);
	rm_fd_and_signal(fd);
	return 0;
}

/* command_sub_attach_volume()
 *
 * Attaches to a volume and returns a created volume structure.
 *
 * Returns:
 * NULL if it could not attach
 *
 * Sets response_result to:
 *
 * AFP_SERVER_RESULT_OKAY:
 * 	Attached properly
 * AFP_SERVER_RESULT_NOVOLUME:
 * 	No volume exists by that name
 * AFP_SERVER_RESULT_ALREADY_MOUNTED:
 * 	Volume is already attached 
 * AFP_SERVER_RESULT_VOLPASS_NEEDED:
 * 	A volume password is needed
 * AFP_SERVER_RESULT_ERROR_UNKNOWN:
 * 	An unknown error occured when attaching.
 *
 */


struct afp_volume * command_sub_attach_volume(struct daemon_client * c,
	struct afp_server * server, char * volname, char * volpassword,
	int * response_result) 
{
	struct afp_volume * using_volume;

	if (response_result) 
		*response_result= 
		AFP_SERVER_RESULT_OKAY;

	using_volume = find_volume_by_name(server,volname);

	if (!using_volume) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"Volume %s does not exist on server %s.\n",volname,
			server->basic.server_name_printable);
		if (response_result) 
			*response_result= AFP_SERVER_RESULT_NOVOLUME;

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
		if (response_result) 
			*response_result= 
				AFP_SERVER_RESULT_ALREADY_MOUNTED;
		goto error;
	}

	if (using_volume->flags & HasPassword) {
		bcopy(volpassword,using_volume->volpassword,AFP_VOLPASS_LEN);
		if (strlen(volpassword)<1) {
			log_for_client((void *) c,AFPFSD,LOG_ERR,"Volume password needed\n");
			if (response_result) 
				*response_result= 
				AFP_SERVER_RESULT_VOLPASS_NEEDED;
			goto error;
		}
	}  else memset(using_volume->volpassword,0,AFP_VOLPASS_LEN);

	using_volume->server=server;

	if (volopen(c,using_volume)) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,"Could not mount volume %s\n",volname);
		if (response_result) 
			*response_result= 
			AFP_SERVER_RESULT_ERROR_UNKNOWN;
		goto error;
	}


	return using_volume;
error:
	return NULL;
}

