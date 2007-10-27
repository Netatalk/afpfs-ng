/*
 *  daemon.c
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
#include "afpclient_log.h"
#include "utils.h"
#include "daemon.h"
#include "commands.h"

#define MAX_ERROR_LEN 1024
#define STATUS_LEN 1024


#define MAX_CLIENT_RESPONSE 2048


static int debug_mode = 0;


static pthread_t ending_thread;

int get_debug_mode(void) 
{
	return debug_mode;
}

static void fuse_forced_ending_hook(void)
{
	struct afp_server * s = get_server_base();
	struct afp_volume * volume;
	int i;
	LOG(AFPFSD,LOG_NOTICE,
		"Unmounting all volumes...\n");
	for (s=get_server_base();s;s=s->next) {
		if (s->connect_state==SERVER_STATE_CONNECTED)
		for (i=0;i<s->num_volumes;i++) {
			volume=&s->volumes[i];
			if (volume->mounted==AFP_VOLUME_MOUNTED)
				LOG(AFPFSD,LOG_NOTICE,
					"   %s\n",volume->mountpoint);
			if (afp_unmount_volume(volume)) return;
		}
	}
}

static void fuse_unmount_volume(struct afp_volume * volume)
{
	if (volume->private) {
		fuse_exit((struct fuse *)volume->private);
		pthread_kill(volume->thread, SIGHUP);
		pthread_join(volume->thread,NULL);
	}
}


static int startup_listener(void) 
{
	int command_fd;
	struct sockaddr_un sa;
	char filename[PATH_MAX];
	int len, rc;

	if ((command_fd=socket(AF_UNIX,SOCK_STREAM,0)) < 0) {
		goto error;
	}
	bzero(&sa,sizeof(sa));
	sa.sun_family = AF_UNIX;
	sprintf(filename,"%s-%d",SERVER_FILENAME,(unsigned int) getuid());
	strcpy(sa.sun_path,filename);
	len = sizeof(sa.sun_family) + strlen(sa.sun_path)+1;

	/* We're going to see if we're already bound here.  Do this by 
	   trying to connect.  We'll use the same sa struct for convenience */

	rc=connect(command_fd,(struct sockaddr *) &sa, len);
	if (rc>=0) {
		close(command_fd);
		LOG(AFPFSD,LOG_ERR,
		"There's another afpfsd running as this user.  Giving up.\n");
		return -1;
	}

	unlink(filename);

	if (bind(command_fd,(struct sockaddr *)&sa,len) < 0)  {
		perror("binding");
		close(command_fd);
		goto error;
	}

	listen(command_fd,5);  /* Just one at a time */

	return command_fd;

error:
	return -1;

}

void close_commands(int command_fd) 
{
	char filename[PATH_MAX];

	sprintf(filename,"%s-%d",SERVER_FILENAME,(unsigned int) getuid());
	close(command_fd);
	unlink(filename);
}

static void usage(void)
{
	printf("Usage: afpfsd [OPTION]\n"
"  -l, --logmethod    Either 'syslog' or 'stdout'"
"  -f, --foreground   Do not fork\n"
"  -d, --debug        Does not fork, logs to stdout\n"
"Version %s\n", AFPFS_VERSION);
}

static struct libafpclient client = {
	.unmount_volume = fuse_unmount_volume, 
	.log_for_client = fuse_log_for_client,
	.forced_ending_hook =fuse_forced_ending_hook,
	.scan_extra_fds = fuse_scan_extra_fds};


int main(int argc, char *argv[]) {

	int option_index=0;
	struct option long_options[] = {
		{"logmethod",1,0,'l'},
		{"foreground",0,0,'f'},
		{"debug",1,0,'d'},
		{0,0,0,0},
	};
	int new_log_method=LOG_METHOD_SYSLOG;
	int dofork=1;
	/* getopt_long()'s return is int; specifying the variable to contain
	 * this return value as char depends on endian-specific behavior,
	 * breaking utterly on big endian (i.e., PowerPC)
	 */
	int c;
	int optnum;
	int command_fd=-1;

	client_setup(&client);

	if (init_uams()<0) return -1;


	while (1) {
		optnum++;
		c = getopt_long(argc,argv,"l:fdh",
			long_options,&option_index);
		if (c==-1) break;
		switch (c) {
			case 'l':
				if (strncmp(optarg,"stdout",6)==0) 	
					new_log_method=LOG_METHOD_STDOUT;
				else if (strncmp(optarg,"syslog",6)==0) 	
					new_log_method=LOG_METHOD_SYSLOG;
				else {
					printf("Unknown log method %s\n",optarg);
					usage();
				}
				break;
			case 'f':
				dofork=0;
				break;
			case 'd':
				dofork=0;
				debug_mode=1;
				new_log_method=LOG_METHOD_STDOUT;
				break;
			case 'h':
			default:
				usage();
				return -1;
		}
	}

	set_log_method(new_log_method);

	/* Here's the logic:
	   - if we're forking, just try setting up the listener, then shut it
	     down so the forked process can set it up again (you can see that
	     we try to set it up again in startup_listener())
	   - if we're not forking it, pass the fd to the listener
	*/

	if ((command_fd=startup_listener())<0) 
		goto error;
	
	if (dofork) {
		close_commands(command_fd);
		command_fd=-1;
	}

	LOG(AFPFSD,LOG_NOTICE,
		"Starting up AFPFS version %s\n",AFPFS_VERSION);

	if ((!dofork) || (fork()==0)) {

		if (command_fd==0) {
			if ((command_fd=startup_listener())<0)
				goto error;
		}

		afp_main_loop(command_fd);
		close_commands(command_fd);
	}

	return 0;

error:
	printf("Could not start afpfsd\n");

	return -1;
}
