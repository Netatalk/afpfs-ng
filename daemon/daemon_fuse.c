/*
 *  daemon_client.c
 *
 *  Copyright (C) 2008 Alex deVries
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
#include "daemon_client.h"
#include "commands.h"

#ifdef __linux
#define FUSE_DEVICE "/dev/fuse"
#else
#define FUSE_DEVICE "/dev/fuse0"
#endif

#define client_string_len(x) \
	(strlen(((struct daemon_client *)(x))->outgoing_string))

static int fuse_result, fuse_errno;

struct afp_volume * global_volume;

struct start_fuse_thread_arg {
	struct afp_volume * volume;
	struct daemon_client * client;
	int changeuid;
};

static void * start_fuse_thread(void * other) 
{
	int fuseargc=0;
	const char *fuseargv[200];
#define mountstring_len (AFP_SERVER_NAME_LEN+1+AFP_VOLUME_NAME_UTF8_LEN+1)
	char mountstring[mountstring_len];
	struct start_fuse_thread_arg * arg = other;
	struct afp_volume * volume = arg->volume;
	struct daemon_client * c = arg->client;
	struct afp_server * server = volume->server;

	int changeuid=arg->changeuid;

	free(arg);

	/* Check to see if we have permissions to access the mountpoint */

	snprintf(mountstring,mountstring_len,"%s:%s",
		server->basic.server_name_printable,
			volume->volume_name_printable);
	fuseargc=0;
	fuseargv[0]=mountstring;
	fuseargc++;
	fuseargv[1]=volume->mountpoint;
	fuseargc++;
/* FIXME
	if (get_debug_mode()) {
*/
	if (0) {
		fuseargv[fuseargc]="-d";
		fuseargc++;
	} else {
		fuseargv[fuseargc]="-f";
		fuseargc++;
	}
	
	if (changeuid) {
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
	fuse_result= 
		afp_register_fuse(fuseargc, (char **) fuseargv,volume);

	fuse_errno=errno;

	pthread_mutex_lock(&volume->startup_condition_mutex);
	volume->started_up=1;
	pthread_cond_signal(&volume->startup_condition_cond);
	pthread_mutex_unlock(&volume->startup_condition_mutex);

	log_for_client((void *) c,AFPFSD,LOG_WARNING,
		"Unmounting volume %s from %s\n",
		volume->volume_name_printable,
                volume->mountpoint);

	return NULL;
}

static int fuse_mount_thread( struct daemon_client * c, struct afp_volume * volume, 
	unsigned int changeuid)
/* Create the new thread and block until we get an answer back */
{
	pthread_mutex_t mutex;
	struct timespec ts;
	struct timeval tv;
	int ret=0;
	struct start_fuse_thread_arg * arg; /* used to pass to args to the thread */
#define FUSE_ERROR_BUFLEN 1024
	char buf[FUSE_ERROR_BUFLEN+1];
	unsigned int buflen=FUSE_ERROR_BUFLEN;
	int response_result;
	int ait;
	int wait = 1;

	/* A bit unusual, this is freed in the start_fuse_thread thread */
	arg = malloc(sizeof(*arg));  

	memset(arg,0,sizeof(*arg));
	arg->client = c;
	arg->volume = volume;
	arg->changeuid=changeuid;

	memset(buf,0,FUSE_ERROR_BUFLEN);

	gettimeofday(&tv,NULL);
	ts.tv_sec=tv.tv_sec;
	ts.tv_sec+=5;
	ts.tv_nsec=tv.tv_usec*1000;
	pthread_mutex_init(&volume->startup_condition_mutex,NULL);
	pthread_cond_init(&volume->startup_condition_cond,NULL);
	volume->started_up=1;
	pthread_mutex_unlock(&volume->startup_condition_mutex);
	

	/* Kickoff a thread to see how quickly it exits.  If
	 * it exits quickly, we have an error and it failed. */

	pthread_create(&volume->thread,NULL,start_fuse_thread,arg);

	if (wait) {
		pthread_mutex_lock(&volume->startup_condition_mutex);
		if (volume->started_up==0)
			ret = pthread_cond_timedwait(
				&volume->startup_condition_cond,
				&volume->startup_condition_mutex,&ts);
		pthread_mutex_unlock(&volume->startup_condition_mutex);
	}
	if (ret==ETIMEDOUT) {
		/* At this point, we never heard anything back from the
		 * fuse thread.  Odd, but we'll need to deal with it.  We
		 * have nothing to report then. */
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"Timeout error when logging into server\n");

		goto error;

	}

/*
 * FIXME: need to handle timeouts, and make sure that arg is still valid */

	report_fuse_errors(buf,&buflen);

	if (buflen>0) 
		log_for_client((void *) c, AFPFSD, LOG_ERR,
			"FUSE reported the following error:\n%s",buf);

	switch (fuse_result) {
	case 0:
	if (volume->mounted==AFP_VOLUME_UNMOUNTED) {
		/* Try and discover why */
		switch(fuse_errno) {
		case ENOENT:
			log_for_client((void *)c,AFPFSD,LOG_ERR,
				"Permission denied, maybe a problem with the fuse device or mountpoint?\n");
			response_result=
				AFP_SERVER_RESULT_MOUNTPOINT_PERM;
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
		response_result=AFP_SERVER_RESULT_TIMEDOUT;
		goto error;
		break;
	default:
		volume->mounted=AFP_VOLUME_UNMOUNTED;
		log_for_client((void *)c,AFPFSD,LOG_NOTICE,
			"Unknown error %d, %d.\n", 
			fuse_result,fuse_errno);
		response_result=AFP_SERVER_RESULT_ERROR_UNKNOWN;
		goto error;
	}

error:
	return -1;

done:
	return 0;

}

int fuse_mount(struct daemon_client * c, volumeid_t * volumeid)
{
	struct afp_server_mount_request * req;
	struct afp_server  * s=NULL;
	struct afp_volume * volume;
	struct afp_connection_request conn_req;
	int ret;
	struct stat lstat;
	char * r;
	int response_result = AFP_SERVER_RESULT_OKAY;

	memset(&volumeid,0,sizeof(volumeid_t));

	req=(void *) c->complete_packet;

	if ((ret=access(req->mountpoint,X_OK))!=0) {
		log_for_client((void *)c,AFPFSD,LOG_DEBUG,
			"Incorrect permissions on mountpoint %s: %s\n",
			req->mountpoint, strerror(errno));
		response_result=AFP_SERVER_RESULT_MOUNTPOINT_PERM;

		goto error;
	}

	if (stat(FUSE_DEVICE,&lstat)) {
		printf("Could not find %s\n",FUSE_DEVICE);
		response_result=AFP_SERVER_RESULT_MOUNTPOINT_NOEXIST;
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
		response_result=AFP_SERVER_RESULT_MOUNTPOINT_PERM;
		goto error;
	}

	log_for_client((void *)c,AFPFSD,LOG_NOTICE,
		"Mounting %s from %s on %s\n",
		(char *) req->url.servername, 
		(char *) req->url.volumename,req->mountpoint);

	if ((s=find_server_by_url(&req->url))==NULL) {
		log_for_client((void *) c,AFPFSD,LOG_ERR,
			"%s is an unknown server\n",req->url.servername);
		response_result=AFP_SERVER_RESULT_NOSERVER;
		goto error;
	}
	/* response_result could be set in command_sub_attach_volume as:
	 * AFP_SERVER_RESULT_OKAY:
	 * AFP_SERVER_RESULT_NOVOLUME:
	 * AFP_SERVER_RESULT_ALREADY_MOUNTED:
	 * AFP_SERVER_RESULT_VOLPASS_NEEDED:
	 * AFP_SERVER_RESULT_ERROR_UNKNOWN:
	 */
	if ((volume=command_sub_attach_volume(c,s,req->url.volumename,
		req->url.volpassword,&response_result))==NULL) {
		goto error;
	}

	volume->extra_flags|=req->volume_options;

	volume->mapping=req->map;
	afp_detect_mapping(volume);

	snprintf(volume->mountpoint,255,req->mountpoint);

	/* Create the new thread and block until we get an answer back */

	if (fuse_mount_thread(c,volume,req->changeuid)<0) goto error;

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
	return response_result;
}

