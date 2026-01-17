/*
 *  commands.c - Stateless daemon command handlers
 *
 *  Copyright (C) 2006 Alex deVries
 *  Copyright (C) 2026 Daniel Markstedt <daniel@mindani.net>
 *
 *  This file contains command handlers for the afpsld stateless daemon.
 *  FUSE-specific commands (MOUNT, UNMOUNT, STATUS, GET_MOUNTPOINT) have
 *  been removed - those are handled by afpfsd (FUSE daemon) instead.
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
#include <time.h>
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
#include "midlevel.h"
#include "map_def.h"
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

#if 0  /* FUSE-specific functions - not used in stateless daemon */
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
#endif  /* End of FUSE-specific functions */

/* process_unmount - REMOVED
 * This command is handled by afpfsd (FUSE daemon), not afpsld.
 * Stateless daemon does not handle FUSE mounts.
 */


static struct afp_volume * find_volume_by_id(volumeid_t * id)
{
	struct afp_server * s;
	struct afp_volume * v;
	 int j;
	printf("[DEBUG] find_volume_by_id: looking for volumeid=%p\n", (void*)*id);
	for (s=get_server_base();s;s=s->next) {
		printf("[DEBUG] find_volume_by_id: checking server %s, num_volumes=%d\n",
			s->server_name_printable, s->num_volumes);
		for (j=0;j<s->num_volumes;j++) {
			v=&s->volumes[j];
			printf("[DEBUG] find_volume_by_id: volume[%d] = %p ('%s')\n",
				j, (void*)v, v->volume_name_printable);
			if (((volumeid_t) v) == *id) {
				printf("[DEBUG] find_volume_by_id: FOUND match!\n");
				return v;
			}
		}
	}
	printf("[DEBUG] find_volume_by_id: no match found\n");
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
		snprintf(response.detach_message, sizeof(response.detach_message),
			"No such volume to detach");
		response.header.result = AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	if (v->mounted != AFP_VOLUME_MOUNTED ) {
		snprintf(response.detach_message, sizeof(response.detach_message),
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

/* process_get_mountpoint - REMOVED
 * This command is handled by afpfsd (FUSE daemon), not afpsld.
 * Stateless daemon does not track mountpoints.
 */

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

	if ((s=find_server_by_name(req->url.servername))==NULL) {
		ret=AFP_SERVER_RESULT_NOTCONNECTED;
		goto done;
	}

	if ((v=find_volume_by_name(s, req->url.volumename))==NULL) {
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

	if ((tmpserver=find_server_by_name(req->url.servername))) {
		/* We're already connected */
		memcpy(&response.server_basic,
			&tmpserver->basic, sizeof(struct afp_server_basic));
	} else {
		struct addrinfo *address;
		if ((address = afp_get_address(NULL, req->url.servername,
			req->url.port)) == NULL) {
			goto error;
		}

		if ((tmpserver=afp_server_init(address))==NULL) {
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

/* process_status - REMOVED
 * This command is handled by afpfsd (FUSE daemon), not afpsld.
 * Status reporting is FUSE mount specific.
 */

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

	if ((server=find_server_by_name(request->url.servername))==NULL) {
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
	if (!response) {
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Out of memory allocating volume list\n");
		goto error;
	}

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
	if (!response) {
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Out of memory in error path\n");
		close_client_connection(c);
		return AFP_SERVER_RESULT_ERROR;
	}

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

	ret = ml_open(v,request->path,request->mode, &fp);

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
		if (!response) {
			log_for_client((void *) c, AFPFSD, LOG_ERR,
				"Out of memory in read\n");
			return AFP_SERVER_RESULT_ERROR;
		}
		result=AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	/* Find the volume */
	if ((v = find_volume_by_id(&request->volumeid))==NULL) {
		response=malloc(len);
		if (!response) {
			log_for_client((void *) c, AFPFSD, LOG_ERR,
				"Out of memory in read\n");
			return AFP_SERVER_RESULT_ERROR;
		}
		result=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	len+=request->length;
	response = malloc(len);
	if (!response) {
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Out of memory allocating %u bytes for read\n", len);
		return AFP_SERVER_RESULT_ERROR;
	}
	data = ((char *) response) + sizeof(struct afp_server_read_response);

	/* Cast fileid back to file_info pointer for stateless operation */
	struct afp_file_info *fp = (struct afp_file_info *)(uintptr_t)request->fileid;
	ret = ml_read(v, NULL, data, request->length, request->start, fp, (int*)&eof);

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

	printf("[DEBUG] process_stat: entry, packet_size=%d, volumeid=%p, path='%s'\n",
		c->completed_packet_size, (void*)request->volumeid, request->path);

	if ((c->completed_packet_size)< sizeof(struct afp_server_stat_request)) {
		printf("[DEBUG] process_stat: packet size error\n");
		result=AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	/* Find the volume */
	if ((v = find_volume_by_id(&request->volumeid))==NULL) {
		printf("[DEBUG] process_stat: volume not found for volumeid=%p\n", (void*)request->volumeid);
		result=AFP_SERVER_RESULT_NOTATTACHED;
		goto done;
	}

	printf("[DEBUG] process_stat: found volume '%s', calling ml_getattr for path '%s'\n",
		v->volume_name, request->path);
	printf("[DEBUG] process_stat: volume->server=%p, server->fd=%d\n", 
		(void*)v->server, v->server ? v->server->fd : -1);
	printf("[DEBUG] process_stat: volume->mounted=%d\n", v->mounted);

	ret = ml_getattr(v,request->path,&response.stat);
	printf("[DEBUG] process_stat: ml_getattr returned %d\n", ret);
	if (ret < 0) {
		printf("[DEBUG] process_stat: ml_getattr error, ret=%d (interpreted as errno: %s)\n", 
			ret, strerror(-ret));
	}

	if (ret == -ENOENT) {
		result = AFP_SERVER_RESULT_ENOENT;
	} else if (ret < 0) {
		result = AFP_SERVER_RESULT_ERROR;
	} else {
		result = AFP_SERVER_RESULT_OKAY;
	}

done:
	printf("[DEBUG] process_stat: done, result=%d\n", result);
	response.header.len=sizeof(struct afp_server_stat_response);
	response.header.result=result;
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

	printf("[DEBUG] process_readdir: entry, packet_size=%d, req->start=%d, req->path='%s'\n",
		c->completed_packet_size, req->start, req->path);

	if (((c->completed_packet_size)< sizeof(struct afp_server_readdir_request)) ||
		(req->start<0)) {
		printf("[DEBUG] process_readdir: packet size or start error\n");
		result=AFP_SERVER_RESULT_ERROR;
		goto error;
	}

	/* Find the volume */
	printf("[DEBUG] process_readdir: looking up volume by id=%p\n", (void*)&req->volumeid);
	if ((v = find_volume_by_id(&req->volumeid))==NULL) {
		printf("[DEBUG] process_readdir: volume not found\n");
		result=AFP_SERVER_RESULT_ENOENT;
		goto error;
	}

	printf("[DEBUG] process_readdir: found volume '%s', calling ml_readdir\n", v->volume_name);

	/* Get the file list */

	ret=ml_readdir(v,req->path,&filebase);
	if (ret) {
		printf("[DEBUG] process_readdir: ml_readdir failed with ret=%d\n", ret);
		result=AFP_SERVER_RESULT_ERROR;
		goto error;
	}

	/* Count how many we have */
	for (fp=filebase;fp;fp=fp->next) numfiles++;

	printf("[DEBUG] process_readdir: found %d files\n", numfiles);

	/* Make sure we're not running off the end */
	if (req->start > numfiles) {
		printf("[DEBUG] process_readdir: req->start (%d) > numfiles (%d)\n", req->start, numfiles);
		result=AFP_SERVER_RESULT_ERROR;
		goto error;
	}

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
	if (!response) {
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Out of memory allocating readdir response\n");
		afp_ml_filebase_free(&filebase);
		return AFP_SERVER_RESULT_ERROR;
	}
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

	/* Make a copy - manually pack afp_file_info into afp_file_info_basic format */
	p=data;
	for (i=0;i<numfiles;i++) {
		struct afp_file_info_basic basic;
		strncpy(basic.name, fp->name, AFP_MAX_PATH);
		basic.creation_date = fp->creation_date;
		basic.modification_date = fp->modification_date;
		basic.unixprivs = fp->unixprivs;
		basic.size = fp->size;
		memcpy(p, &basic, sizeof(struct afp_file_info_basic));
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
	printf("[DEBUG] process_readdir: error path, result=%d\n", result);
	response = (void*) malloc(len);
	if (!response) {
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Out of memory in readdir error path\n");
		afp_ml_filebase_free(&filebase);
		close_client_connection(c);
		return AFP_SERVER_RESULT_ERROR;
	}
	result=AFP_SERVER_RESULT_ERROR;
	response->numfiles=0;

done:
	printf("[DEBUG] process_readdir: done, result=%d, numfiles=%d\n", result, response->numfiles);
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

	if ((s=find_server_by_name(req->url.servername))) {
		response_result=AFP_SERVER_RESULT_ALREADY_CONNECTED;
           	goto done;
        }

	/* Initialize connection request */
	conn_req.uam_mask = req->uam_mask;
	memcpy(&conn_req.url, &req->url, sizeof(struct afp_url));

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


	if ((s=afp_server_full_connect(c, &conn_req))==NULL) {
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
	if (!response) {
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Out of memory allocating connect response\n");
		close_client_connection(c);
		return AFP_SERVER_RESULT_ERROR;
	}
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

/* process_mount - REMOVED
 * This command is handled by afpfsd (FUSE daemon), not afpsld.
 * Stateless daemon does not handle FUSE mounts.
 */


	
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
	struct addrinfo * address = NULL;

	printf("[DEBUG] process_attach: entry, packet_size=%d\n", c->completed_packet_size);

	if ((c->completed_packet_size) < sizeof(struct afp_server_attach_request)) {
		printf("[DEBUG] process_attach: packet size too small\n");
		goto error;
	}

	req=(void *) c->complete_packet;

	printf("[DEBUG] process_attach: servername='%s', volumename='%s'\n",
		req->url.servername, req->url.volumename);

	log_for_client((void *)c,AFPFSD,LOG_NOTICE,
		"Attaching volume %s on server %s\n",
		(char *) req->url.servername,
		(char *) req->url.volumename);

	/* Resolve the server name to an address and find by address
	 * This allows matching by IP address even if server reports a different hostname */
	if ((address = afp_get_address((void *)c, req->url.servername, req->url.port)) == NULL) {
		printf("[DEBUG] process_attach: could not resolve address for '%s'\n", req->url.servername);
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"Could not resolve address for server %s\n",req->url.servername);
		goto error;
	}

	if ((s=find_server_by_address(address))==NULL) {
		printf("[DEBUG] process_attach: server '%s' not found by address\n", req->url.servername);
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"Not yet connected to server %s\n",req->url.servername);
		freeaddrinfo(address);
		goto error;
	}

	freeaddrinfo(address);

	printf("[DEBUG] process_attach: found server '%s'\n", s->server_name_printable);

	/* Always call command_sub_attach_volume, which handles:
	 * - Finding the volume by name
	 * - Checking if already mounted
	 * - Opening AFP connection via volopen() if needed
	 */
	printf("[DEBUG] process_attach: calling command_sub_attach_volume\n");
	if ((volume=command_sub_attach_volume(c,s,req->url.volumename,
		req->url.volpassword,&response_result))==NULL) {
		/* command_sub_attach_volume sets response_result appropriately */
		goto error;
	}

	/* If volume was already mounted, command_sub_attach_volume returns NULL with
	 * response_result=AFP_SERVER_RESULT_ALREADY_MOUNTED. We need to handle this. */
	if (response_result == AFP_SERVER_RESULT_ALREADY_MOUNTED) {
		/* Find the volume again for returning its ID */
		volume = find_volume_by_name(s, req->url.volumename);
		if (!volume) {
			response_result = AFP_SERVER_RESULT_ERROR;
			goto error;
		}
		/* This is success - volume is mounted and ready */
		response_result = AFP_SERVER_RESULT_OKAY;
	}

	volume->extra_flags|=req->volume_options;

	response_result=AFP_SERVER_RESULT_OKAY;
	goto done;
error:
	printf("[DEBUG] process_attach: error path, volume=%p\n", (void*)volume);
	if ((s) && (!something_is_mounted(s))) {
		afp_server_remove(s);
	}
	response_result=AFP_SERVER_RESULT_ERROR;

done:
	printf("[DEBUG] process_attach: done label, volume=%p, response_result=%d\n",
		(void*)volume, response_result);
	signal_main_thread();

	response_len = sizeof(struct afp_server_attach_response) +
		client_string_len(c);
	r = malloc(response_len);
	if (!r) {
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Out of memory allocating attach response\n");
		close_client_connection(c);
		return AFP_SERVER_RESULT_ERROR;
	}
	memset(r,0,response_len);
	response = (void *) r;
	response->header.result=response_result;
	response->header.len=response_len;
	if (volume) {
		response->volumeid=(volumeid_t) volume;
		printf("[DEBUG] process_attach: returning volumeid=%p for volume '%s'\n",
			(void*)volume, volume->volume_name_printable);
	} else {
		printf("[DEBUG] process_attach: volume is NULL, not setting volumeid\n");
	}

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
	case AFP_SERVER_COMMAND_ATTACH:
		ret=process_attach(c);
		break;
	case AFP_SERVER_COMMAND_DETACH:
		ret=process_detach(c);
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

	/* FUSE-specific commands - not supported by afpsld stateless daemon */
	case AFP_SERVER_COMMAND_MOUNT:
	case AFP_SERVER_COMMAND_UNMOUNT:
	case AFP_SERVER_COMMAND_STATUS:
	case AFP_SERVER_COMMAND_GET_MOUNTPOINT:
	case AFP_SERVER_COMMAND_SUSPEND:
	case AFP_SERVER_COMMAND_RESUME:
		log_for_client((void *)c,AFPFSD,LOG_ERR,
			"Command %d not supported by afpsld (stateless daemon). "
			"Use afpfsd (FUSE daemon) instead.\n", req->command);
		ret=AFP_SERVER_RESULT_NOTSUPPORTED;
		break;

	default:
		log_for_client((void *)c,AFPFSD,LOG_ERR,"Unknown command %d\n", req->command);
		ret=AFP_SERVER_RESULT_ERROR;
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

	printf("[DEBUG] command_sub_attach_volume: entry, volname='%s'\n", volname);

	if (response_result)
		*response_result=
		AFP_SERVER_RESULT_OKAY;

	using_volume = find_volume_by_name(server,volname);

	if (!using_volume) {
		printf("[DEBUG] command_sub_attach_volume: volume '%s' not found on server\n", volname);
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

	printf("[DEBUG] command_sub_attach_volume: found volume, mounted=%d\n", using_volume->mounted);

	if (using_volume->mounted==AFP_VOLUME_MOUNTED) {
		printf("[DEBUG] command_sub_attach_volume: volume already mounted\n");
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
			printf("[DEBUG] command_sub_attach_volume: password needed but not provided\n");
			log_for_client((void *) c,AFPFSD,LOG_ERR,"Volume password needed\n");
			if (response_result)
				*response_result=
				AFP_SERVER_RESULT_VOLPASS_NEEDED;
			goto error;
		}
	}  else memset(using_volume->volpassword,0,AFP_VOLPASS_LEN);

	using_volume->server=server;

	printf("[DEBUG] command_sub_attach_volume: calling volopen\n");
	if (volopen(c,using_volume)) {
		printf("[DEBUG] command_sub_attach_volume: volopen failed\n");
		log_for_client((void *) c,AFPFSD,LOG_ERR,"Could not mount volume %s\n",volname);
		if (response_result)
			*response_result=
			AFP_SERVER_RESULT_ERROR_UNKNOWN;
		goto error;
	}

	printf("[DEBUG] command_sub_attach_volume: volopen succeeded, detecting mapping\n");
	printf("[DEBUG] command_sub_attach_volume: volume->mapping before detect=%d\n", using_volume->mapping);
	afp_detect_mapping(using_volume);
	printf("[DEBUG] command_sub_attach_volume: volume->mapping after detect=%d\n", using_volume->mapping);

	printf("[DEBUG] command_sub_attach_volume: success, returning volume=%p\n", (void*)using_volume);
	return using_volume;
error:
	printf("[DEBUG] command_sub_attach_volume: error path, returning NULL\n");
	return NULL;
}

