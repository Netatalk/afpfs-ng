/*
 *  loop.c
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
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>

#include "afp.h"
#include "dsi.h"
#include "utils.h"

#define SIGNAL_TO_USE SIGUSR2




static unsigned char exit_program=0;

static pthread_t ending_thread;
static pthread_t main_thread = NULL;

void trigger_exit(void)
{
	exit_program=1;
}

void termination_handler(int signum)
{
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
        syslog(LOG_ERR,"adding %d",fd);

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

void signal_main_thread(void)
{
	if (main_thread) 
		pthread_kill(main_thread,SIGNAL_TO_USE);
}

static void just_end_it_now(void)
{
	struct afp_server * s = get_server_base();
	struct afp_volume * volume;
	int i;

	if (libafpclient->forced_ending_hook) 
		libafpclient->forced_ending_hook();
	exit_program=2;
	signal_main_thread();
}

/*This is a hack to handle a problem where the first pthread_kill doesnt' work*/
static unsigned char firsttime=0; 
void add_fd_and_signal(int fd)
{
	add_fd(fd);
	signal_main_thread();
	if (!firsttime) {
		firsttime=1;
		signal_main_thread();
	}
	
}

void rm_fd_and_signal(int fd)
{
	rm_fd(fd);
	signal_main_thread();
}

void loop_disconnect(struct afp_server *s)
{

        if (s->connect_state!=SERVER_STATE_CONNECTED)
                return;

        rm_fd_and_signal(s->fd);

	/* Handle disconnect */
        close(s->fd);

	s->connect_state=SERVER_STATE_DISCONNECTED;
	s->need_resume=1;
}


static void loop_reconnect(struct afp_server *s)
{

        add_fd_and_signal(s->fd);
}

static void unmount_volume(struct afp_volume * volume)
{
	if (volume->private) {
		fuse_exit((struct fuse *)volume->private);
		pthread_kill(volume->thread, SIGHUP);
		pthread_join(volume->thread,NULL);
	}
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
				loop_disconnect(s);
				return -1;
			}
			return 1;
		}
	}
	return 0;
}

static void deal_with_server_signals(fd_set *set, int * max_fd) 
{

	if (exit_program==1) {
		pthread_create(&ending_thread,NULL,just_end_it_now,NULL);
	}

}


int afp_main_loop(int command_fd) {
	fd_set ords, oeds;
	struct timespec tv;
	int ret;
	int new_fd;
	int fderrors=0;
	sigset_t sigmask, orig_sigmask;

	main_thread=pthread_self();

	FD_ZERO(&rds);
	if (command_fd>=0) 
		add_fd(command_fd);



	sigemptyset(&sigmask);
	sigaddset(&sigmask,SIGNAL_TO_USE);
	sigprocmask(SIG_BLOCK,&sigmask,&orig_sigmask);

	signal(SIGNAL_TO_USE,termination_handler);
	signal(SIGINT,termination_handler);
        syslog(LOG_ERR,"%s","main loop 2");
	while(1) {

		ords=rds;
		oeds=rds;
		tv.tv_sec=30;
		tv.tv_nsec=0;
		ret=pselect(max_fd,&ords,NULL,&oeds,&tv,&orig_sigmask);
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
			if (libafpclient->scan_extra_fds) {
				if (libafpclient->scan_extra_fds(
					command_fd,&ords,&max_fd)>0)
					continue;
			}
		}
	}

error:
	return -1;

}

