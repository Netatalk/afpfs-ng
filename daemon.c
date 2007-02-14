/*
 *  daemon.c
 *
 *  Copyright (C) 2006 Alex deVries
 *
 */

#include <fuse.h>
#include <fuse/fuse_opt.h>
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
#include "afp_server.h"
#include "log.h"
#include "utils.h"
#include "daemon.h"

#define MAX_ERROR_LEN 1024
#define STATUS_LEN 1024


#define MAX_CLIENT_RESPONSE 2048

#define SIGNAL_TO_USE SIGUSR2

static int debug_mode = 0;

static unsigned char exit_program=0;
static pthread_t main_thread;

static pthread_t ending_thread;

int get_debug_mode(void) 
{
	return debug_mode;
}


void trigger_exit(void)
{
	exit_program=1;
}

void termination_handler(int signum)
{
	LOG(AFPFSD,LOG_DEBUG,"Got a signal %d\n",signum);
	if (signum==SIGINT) {
		trigger_exit();
	}

	signal(SIGNAL_TO_USE, termination_handler);
		
}

#define max(a,b) (((a)>(b)) ? (a) : (b))

static fd_set rds;
static int max_fd=0;

static void add_fd(int fd)
{
	FD_SET(fd,&rds);
	if ((fd+1) > max_fd) max_fd=fd+1;
}

static void rm_fd(int fd)
{
	int i;
	FD_CLR(fd,&rds);
	for (i=max_fd;i>=0;i--)
		if (FD_ISSET(i,&rds)) {
			max_fd=i;
			break;
		}

	max_fd++;
}

static void just_end_it_now(void)
{
	struct afp_server * s = get_server_base();
	struct afp_volume * volume;
	int i;
	LOG(AFPFSD,LOG_NOTICE,
		"Unmouning all volumes...\n");
	for (s=get_server_base();s;s=s->next) {
		for (i=0;i<s->num_volumes;i++) {
			volume=&s->volumes[i];
			if (volume->mounted==AFP_VOLUME_MOUNTED)
				LOG(AFPFSD,LOG_NOTICE,
					"   %s\n",volume->mountpoint);
			if (afp_unmount_volume(volume)) return;
		}
	}
	exit_program=2;
	pthread_kill(main_thread,SIGNAL_TO_USE);
}

/*This is a hack to handle a problem where the first pthread_kill doesnt' work*/
static unsigned char firsttime=0; 
void add_fd_and_signal(int fd)
{
	int ret;
	add_fd(fd);
	ret=pthread_kill(main_thread,SIGNAL_TO_USE);
	if (!firsttime) {
		firsttime=1;
		pthread_kill(main_thread,SIGNAL_TO_USE);
	}
	
}

void rm_fd_and_signal(int fd)
{
	rm_fd(fd);
	pthread_kill(main_thread,SIGNAL_TO_USE);
}

void signal_main_thread(void)
{
	pthread_kill(main_thread,SIGNAL_TO_USE);
}

static int process_server_fds(fd_set * set, int max_fd, int ** onfd)
{

	struct afp_server * s;
	int ret;
	s  = get_server_base();
	for (;s;s=s->next) {
		if (FD_ISSET(s->fd,set)) {
			ret=dsi_recv(s);
			*onfd=&s->fd;
			if (ret==-1) {
				afp_server_disconnect(s);
				return -1;
			}
			return 1;
		}
	}
	return 0;
}

static void deal_with_server_signals(fd_set *set, int * max_fd) 
{

	LOG(AFPFSD,LOG_DEBUG,
		"Got a server signal, %d\n",exit_program);
	if (exit_program) {
		pthread_create(&ending_thread,NULL,just_end_it_now,NULL);
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

int listen_commands(int * command_fd) {
	fd_set ords;
	struct timespec tv;
	int ret;
	int new_fd;
	int fderrors=0;
	sigset_t sigmask, orig_sigmask;

	if (*command_fd==0) {
		if ((*command_fd=startup_listener())<0) 
			goto error;
	}

	FD_ZERO(&rds);
	add_fd(*command_fd);

	sigemptyset(&sigmask);
	sigaddset(&sigmask,SIGNAL_TO_USE);
	sigprocmask(SIG_BLOCK,&sigmask,&orig_sigmask);

	signal(SIGNAL_TO_USE,termination_handler);
	signal(SIGINT,termination_handler);

	while(1) {

		ords=rds;
		tv.tv_sec=30;
		tv.tv_nsec=0;
		ret=pselect(max_fd,&ords,NULL,NULL,&tv,&orig_sigmask);
		if (ret<0) {
			switch(errno) {
			case EINTR:
				deal_with_server_signals(&rds,&max_fd);
				break;
			case EBADF:
				if (fderrors > 100) {
					LOG(AFPFSD,LOG_ERR,
					"Too many fd errors, exiting\n");
					break;
				} 
				fderrors++;
				continue;
			}
			if (exit_program==2) break;
			continue;
		}
		fderrors=0;
		if (ret==0) {
			/* Timeout */
		} else {
			int * onfd;
			switch (process_server_fds(&ords,max_fd,&onfd)) {
			case -1: 
				continue;
			case 1:
				continue;
			}
			if (FD_ISSET(*command_fd,&ords)) {
				struct sockaddr_un new_addr;
				socklen_t new_len = sizeof(struct sockaddr_un);
				new_fd=accept(*command_fd,(struct sockaddr *) &new_addr,&new_len);
				if (new_fd>=0) {
					LOG(AFPFSD,LOG_DEBUG,
						"Got connection %d\n",new_fd);
					add_client(new_fd);
					add_fd(new_fd);

				}
				continue;
			}
			switch (process_client_fds(&ords,max_fd,&onfd)) {
			case -1:
				rm_fd(*onfd);
				close(*onfd);
				*onfd=0;
				continue;
			case 1:
				continue;
			}
			LOG(AFPFSD,LOG_ERR,
				"**** Unknown fd\n");
			sleep(10);
		}
	}

error:
	return -1;

}

static void usage(void)
{
	printf("Usage: afpfsd [OPTION]\n"
"  -l, --logmethod    Either 'syslog' or 'stdout'"
"  -f, --foreground   Do not fork\n"
"  -d, --debug        Does not fork, logs to stdout\n"
"Version %s\n", AFPFS_VERSION);
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
	char c;
	int optnum;
	int command_fd;

	if (init_uams()<0) return -1;

	main_thread=pthread_self();

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
		command_fd=0;
	}

	LOG(AFPFSD,LOG_NOTICE,
		"Starting up AFPFS version %s\n",AFPFS_VERSION);

	if ((!dofork) || (fork()==0)) {
		listen_commands(&command_fd);
		close_commands(command_fd);
	}

	return 0;

error:
	printf("Could not start afpfsd\n");

}
