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

static int loop_started=0;
static pthread_cond_t loop_started_condition;
static pthread_mutex_t loop_started_mutex;


void trigger_exit(void)
{
	exit_program=1;
}

void sigpipe_handler(int signum)
{
	printf("sigpipe!\n");
	signal(SIGPIPE,sigpipe_handler);
}

void termination_handler(int signum)
{
	signal(SIGTERM,termination_handler);
	signal(SIGINT,termination_handler);
	signal(SIGNAL_TO_USE, termination_handler);
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		trigger_exit();
		break;
	default:
		break;

	}
		
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

void signal_main_thread(void)
{
	if (main_thread) 
		pthread_kill(main_thread,SIGNAL_TO_USE);
}

static int ending=0;
void * just_end_it_now(void * ignore)
{

	if (ending) goto out;
	ending=1;
	if (libafpclient->forced_ending_hook) 
		libafpclient->forced_ending_hook();
	exit_program=2;
	signal_main_thread();
out:
	return NULL;
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

static int process_server_fds(fd_set * set, int max_fd, int ** onfd)
{

	struct afp_server * s;
	int ret;
	s  = get_server_base();
	for (;s;s=s->next) {
		if (s->next==s) {
			printf("Danger, recursive loop, %p\n",(void *) s);
			return -1;
		}
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

void afp_wait_for_started_loop(void) 
{
	if (loop_started) return;

	pthread_cond_wait(&loop_started_condition,&loop_started_mutex);

}

static void * afp_main_quick_startup_thread(void * other)
{
	afp_main_loop(-1);
	return NULL;
}


int afp_main_quick_startup(pthread_t * thread)
{
	pthread_t loop_thread;
	pthread_create(&loop_thread,NULL,afp_main_quick_startup_thread,NULL);
	if (thread) 
		memcpy(thread,&loop_thread,sizeof(pthread_t));
	return 0;
}

/* This allows for main loop debugging */
#define DEBUG_LOOP 1

int afp_main_loop(int command_fd) {
	fd_set ords, oeds;
	struct timespec tv;
	int ret;
	int fderrors=0;
	int localerror=0;
	sigset_t sigmask, orig_sigmask;

	main_thread=pthread_self();

	FD_ZERO(&rds);
	if (command_fd>=0) 
		add_fd(command_fd);



	sigemptyset(&sigmask);
	sigaddset(&sigmask,SIGNAL_TO_USE);
	sigprocmask(SIG_BLOCK,&sigmask,&orig_sigmask);

	signal(SIGNAL_TO_USE,termination_handler);
	signal(SIGTERM,termination_handler);
	signal(SIGINT,termination_handler);
	signal(SIGPIPE,sigpipe_handler);

	#ifdef DEBUG_LOOP
	printf("-- Starting up loop\n");
	#endif
	while(1) {
		#ifdef DEBUG_LOOP
		printf("-- Setting new fds\n");
{int j; for (j=0;j<16;j++) if (FD_ISSET(j,&rds)) printf("fd %d is set\n",j);}
		#endif

		ords=rds;
		oeds=rds;
		if (loop_started) {
			tv.tv_sec=30;
			tv.tv_nsec=0;
		} else {
			tv.tv_sec=0;
			tv.tv_nsec=0;
		}

		#ifdef DEBUG_LOOP
		printf("-- Starting new select\n");
		#endif

		ret=pselect(max_fd,&ords,NULL,&oeds,&tv,&orig_sigmask);

		localerror=errno;

		if (exit_program==2) break;
		if (exit_program==1) {
			pthread_create(&ending_thread,NULL,just_end_it_now,NULL);
		}

	#ifdef DEBUG_LOOP
	printf("-- Got %d from select, %d\n",ret,localerror);
	if (ret<0) perror("select");
	#endif
		if (ret<0) {
			switch(localerror) {
			case EINTR:
				#ifdef DEBUG_LOOP
				printf("Dealing with an interrupted signal\n");
				#endif
				deal_with_server_signals(&rds,&max_fd);
				break;
			case EBADF:
				#ifdef DEBUG_LOOP
				printf("Dealing with a bad file descriptor\n");
				#endif
				if (fderrors > 100) {
					log_for_client(NULL,AFPFSD,LOG_ERR,
					"Too many fd errors, exiting\n");
					sleep(10);
					break;
				} 
				fderrors++;
				continue;
			default:
				#ifdef DEBUG_LOOP
				printf("Dealing with some other error, %d\n",
					errno);
				#endif
				if (libafpclient->scan_extra_fds) {
					#ifdef DEBUG_LOOP
					printf("** Other error\n");
					#endif
					ret=libafpclient->scan_extra_fds(
						command_fd,&ords,&rds,&oeds,
						&max_fd,errno);
				}
				continue;
			}
			continue;
		}
		fderrors=0;
		if (ret==0) {
			/* Timeout */
			if (loop_started==0) {
				loop_started=1;
				pthread_cond_signal(&loop_started_condition);
				if (libafpclient->loop_started) 
					libafpclient->loop_started();
			}
		} else {
			int * onfd;
			int clientfd = -1;
			fderrors=0;
			switch (process_server_fds(&ords,max_fd,&onfd)) {
			case -1: 
				continue;
			case 1:
				continue;
			}
			if (libafpclient->scan_extra_fds) {
				#ifdef DEBUG_LOOP
				printf("** Scanning client fds\n");
				#endif
				/* <0 nothing to handle */
				/* 0  handled, continue with clientfd*/
				/* 1  close clientfd */
				ret=libafpclient->scan_extra_fds(
					command_fd,&ords,&rds,&oeds,
					&max_fd,0);
				continue;
			}
		}
	}
	#ifdef DEBUG_LOOP
	printf("-- done with loop altogether\n");
	#endif


error:
	pthread_detach(ending_thread);
	return -1;
}

