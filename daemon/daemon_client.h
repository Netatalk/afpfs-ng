#ifndef __DAEMON_CLIENT_H_
#define __DAEMON_CLIENT_H_

#include <pthread.h>

#define AFP_CLIENT_INCOMING_BUF 8192

#define DAEMON_NUM_CLIENTS 10

struct daemon_client {
	char incoming_string[AFP_CLIENT_INCOMING_BUF];
	int incoming_size;
	char * a;

	char complete_packet[AFP_CLIENT_INCOMING_BUF];
	int completed_packet_size;
	pthread_mutex_t command_string_mutex;

	char outgoing_string[1000 + MAX_CLIENT_RESPONSE];
	int fd;
	int lock;
	char * shmem;
	int toremove;
	int pending;
	pthread_t processing_thread;
	pthread_mutex_t processing_mutex;
	int used;
};

unsigned int send_command(struct daemon_client * c, 
        unsigned int len, const char * data);

int continue_client_connection(struct daemon_client * c);
int close_client_connection(struct daemon_client * c);
int remove_client(struct daemon_client ** toremove);
void remove_command(struct daemon_client *c);






#endif
