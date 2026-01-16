/*
 *  daemon.c - Stateless daemon main loop
 *
 *  Copyright (C) 2006 Alex deVries
 *  Copyright (C) 2026 Daniel Markstedt <daniel@mindani.net>
 *
 *  This is the main loop for afpsld (stateless daemon).
 *  FUSE-specific code has been removed - use afpfsd for FUSE mounts.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>

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
#include <sys/socket.h>

#include "afp.h"

#include "dsi.h"
#include "afpfsd.h"
#include "utils.h"
#include "daemon.h"
#include "commands.h"
#include "daemon_socket.h"
#include "daemon_signals.h"

#define MAX_ERROR_LEN 1024
#define STATUS_LEN 1024

static int daemon_log_method=LOG_METHOD_SYSLOG;

static int debug_mode = 0;
static char commandfilename[PATH_MAX];

int get_debug_mode(void) 
{
	return debug_mode;
}

static void daemon_set_log_method(int new_method)
{
	daemon_log_method=new_method;
}

static void daemon_log_for_client(void * priv,
	enum logtypes logtype, int loglevel, const char *message) {
	int len = 0;
	struct daemon_client * c = priv;

	if (c) {
		len = strlen(c->outgoing_string);
		snprintf(c->outgoing_string+len,
		sizeof(c->outgoing_string) - len,
		"%s", message);
	} else {
		if (daemon_log_method & LOG_METHOD_SYSLOG)
			syslog(LOG_INFO, "%s", message);
		if (daemon_log_method & LOG_METHOD_STDOUT)
			printf("%s",message);
	}
}

void daemon_forced_ending_hook(void)
{
	/* For stateless daemon, we only need to clean up client connections.
	 * Volume unmounting is handled by afpfsd (FUSE daemon), not afpsld.
	 */
	struct afp_server * s = get_server_base();
	int i;

	/* Disconnect from all servers */
	for (s=get_server_base();s;s=s->next) {
		if (s->connect_state==SERVER_STATE_CONNECTED) {
			for (i=0;i<s->num_volumes;i++) {
				struct afp_volume * volume=&s->volumes[i];
				if (volume->mounted==AFP_VOLUME_MOUNTED) {
					log_for_client(NULL,AFPFSD,LOG_NOTICE,
						"Disconnecting from volume %s\n",
						volume->volume_name);
					afp_unmount_volume(volume);
				}
			}
		}
	}

	remove_all_clients();
}

int daemon_unmount_volume(struct afp_volume * volume)
{
	/* Stateless daemon doesn't use FUSE, so no fuse_exit() needed.
	 * Just mark volume as unmounted. FUSE unmounting is in afpfsd.
	 */
	if (!volume) {
		return -1;
	}

	/* For stateless daemon, we just need to mark it as unmounted.
	 * The actual AFP disconnect will be handled elsewhere. */
	return 0;
}


static int startup_listener(void)
{
	return daemon_socket_create(commandfilename, DAEMON_NUM_CLIENTS);
}

void close_commands(int command_fd)
{
	daemon_socket_close(command_fd, commandfilename);
}

static void usage(void)
{
	printf("Usage: afpfsd [OPTION]\n"
"  -l, --logmethod    Either 'syslog' or 'stdout'"
"  -f, --foreground   Do not fork\n"
"  -d, --debug        Does not fork, logs to stdout\n"
"Version %s\n", AFPFS_VERSION);
}

static int remove_other_daemon(void)
{
	int ret = daemon_socket_cleanup_stale(commandfilename);
	if (ret < 0) {
		log_for_client(NULL, AFPFSD, LOG_NOTICE,
			"Daemon is already running and alive\n");
	}
	return ret;
}


static struct libafpclient client = {
	.unmount_volume = daemon_unmount_volume,
	.log_for_client = daemon_log_for_client,
	.forced_ending_hook =daemon_forced_ending_hook,
	.scan_extra_fds = daemon_scan_extra_fds
};

static int daemon_register_afpclient(void)
{
	libafpclient_register(&client);
	return 0;
}

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

	daemon_register_afpclient();

	if (init_uams()<0) return -1;


	while (1) {
		optnum++;
		c = getopt_long(argc,argv,"l:fdh",
			long_options,&option_index);
		if (c==-1) break;
		switch (c) {
			case 'l':
				if (strncmp(optarg,"stdout",6)==0) 	
					daemon_set_log_method(LOG_METHOD_STDOUT);
				else if (strncmp(optarg,"syslog",6)==0) 	
					daemon_set_log_method(LOG_METHOD_SYSLOG);
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

	daemon_set_log_method(new_log_method);

	snprintf(commandfilename, sizeof(commandfilename), "%s-%d",
	         SERVER_FILENAME, (unsigned int) geteuid());

	if (remove_other_daemon() < 0) {
		return -1;
	}


	if ((!dofork) || (fork()==0)) {
		if ((command_fd=startup_listener())<0)
			goto error;

		/* Install SIGCHLD handler to immediately reap child processes */
		daemon_install_sigchld_handler();

		log_for_client(NULL, AFPFSD,LOG_NOTICE,
			"Starting up AFPFS version %s\n",AFPFS_VERSION);

		afp_main_loop(command_fd);
		close_commands(command_fd);
	}



	return 0;

error:
	printf("Could not start afpfsd\n");

	return -1;
}
