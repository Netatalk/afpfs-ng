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
#include "daemon_client.h"
#include "commands.h"

#define AFP_CLIENT_INCOMING_BUF 8192

#define client_string_len(x) \
	(strlen(((struct daemon_client *)(x))->outgoing_string))

static struct daemon_client client_pool[DAEMON_NUM_CLIENTS];

/* Used to protect the pool searching, creation and deletion */
pthread_mutex_t client_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

int remove_client(struct daemon_client ** toremove) 
{
	struct daemon_client * c, * prev=NULL;
	int ret=0;
	int i;
printf("--- remove_client\n");

	if ((toremove==NULL) || (*toremove==NULL)) return -1;
printf("rc1\n");

	pthread_mutex_lock(&client_pool_mutex);
printf("rc2\n");

	/* Go find the client */
	for (i=0;i<DAEMON_NUM_CLIENTS;i++) {
printf("searching client %d\n",i);
		if (*toremove==&client_pool[i]) {
			client_pool[i].used=0;
			if (pthread_kill((*toremove)->processing_thread,0))
				perror("pthread_kill");
			if (pthread_join((*toremove)->processing_thread,NULL))
				perror("pthread_join");
			goto done;
		}
	}

	ret=-1;
done:
	pthread_mutex_unlock(&client_pool_mutex);
	return ret;
}

void remove_all_clients(void) 
{
	struct daemon_client * c, *c2;
	int i;

printf("--- Removing all clients\n");
	
	pthread_mutex_lock(&client_pool_mutex);

	for (i=0;i<DAEMON_NUM_CLIENTS;i++) {
		client_pool[i].used=0;
	}

	pthread_mutex_unlock(&client_pool_mutex);
}


int continue_client_connection(struct daemon_client * c)
{
	if (c->toremove) {
		c->pending=0;
		remove_client(&c);
	}
	add_fd_and_signal(c->fd);
	c->incoming_size=0;
	return 0;
}

int close_client_connection(struct daemon_client * c)
{
	c->incoming_size=0;
	add_fd_and_signal(c->fd);

	if ((!c) || 
		(c->fd==0)) return -1;
	rm_fd_and_signal(c->fd);
	close(c->fd);
	remove_client(&c);
	return 0;
}


static int add_client(int fd) 
{
	struct daemon_client * c, *newc;
	int count=0;
	int i;

	pthread_mutex_lock(&client_pool_mutex);

printf("--- creating new client, fd %d\n",fd);
	for (i=0;i<DAEMON_NUM_CLIENTS;i++) {
		c=&client_pool[i];
		if (c->used==0) goto found;

	}

	pthread_mutex_unlock(&client_pool_mutex);

	/* We didn't find anything */
	return -1;

found:
	pthread_mutex_unlock(&client_pool_mutex);
	memset(c,0,sizeof(*c));
	c->fd=fd;
	c->used=1;

	return 0;
}

static int process_client_fds(fd_set * set, int max_fd, 
	struct daemon_client ** found)
{

	struct daemon_client * c;
	int ret;
	int i;

	*found=NULL;

	pthread_mutex_lock(&client_pool_mutex);

	for (i=0;i<DAEMON_NUM_CLIENTS;i++) {
		c=&client_pool[i];
		if ((c->used) && (FD_ISSET(c->fd,set))) {
			goto found;
		}
	}

	/* We never found it */
	pthread_mutex_unlock(&client_pool_mutex);

	return 0;

found:
	pthread_mutex_unlock(&client_pool_mutex);
	if (found) *found=c;
	ret=process_command(c);
	if (ret<0) return -1;
	return 1;
}

int daemon_scan_extra_fds(int command_fd, fd_set *set, 
		fd_set * toset, fd_set *exceptfds, int * max_fd, int err)
{

	struct sockaddr_un new_addr;
	socklen_t new_len = sizeof(struct sockaddr_un);
	struct daemon_client * found, *c;
	int i, found_fd=0;

	if (err) {
printf("fsefd 1, commandfd: %d\n",command_fd);
		for (i=0;i<*max_fd;i++) {
			if (FD_ISSET(i,exceptfds)) {
				found_fd=i;
			}
		}
printf("fsefd 1a, fd: %d\n",found_fd);
		if (found_fd==0) return -1;

		for (i=0;i<DAEMON_NUM_CLIENTS;i++) {
			c=&client_pool[i];
printf("fsefd 2\n");
			if (FD_ISSET(c->fd,exceptfds)) {
printf("fsefd 3\n");
				remove_client(&c);
				return 1;
			}
printf("fsefd 5\n");
		}
	}
printf("fsefd 6\n");


	if (FD_ISSET(command_fd,set)) {
		int new_fd=
			accept(command_fd,
			(struct sockaddr *) &new_addr,&new_len);
printf("Accepting new one, %d\n",new_fd);

		if (new_fd>=0) {
			add_client(new_fd);
			if ((new_fd+1) > *max_fd) *max_fd=new_fd+1;
		}
		FD_SET(new_fd,toset);
		return 0;
	}

	if ((exceptfds) && (FD_ISSET(command_fd,exceptfds))) {
		printf("We have an exception\n");
		return 0;
	}

	switch (process_client_fds(set,*max_fd,&found)) {
	case -1: /* we're done with found->fd */
		if (found) {
			FD_CLR(found->fd,toset);
			close(found->fd);
			remove_client(&found);
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
printf("***SLEEPING!\n");
	sleep(10);

	return -1;
}


unsigned int send_command(struct daemon_client * c, 
	unsigned int len, const char * data)
{
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


