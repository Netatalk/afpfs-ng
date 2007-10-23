
#ifndef __CLIENT_H_
#define __CLIENT_H_

#include <syslog.h>

#define MAX_CLIENT_RESPONSE 2048


enum loglevels {
        AFPFSD,
};


struct client {
	char incoming_string[1024];
	int incoming_size;
	/* char client_string[sizeof(struct afp_server_response) + MAX_CLIENT_RESPONSE]; */
	char client_string[1000 + MAX_CLIENT_RESPONSE]; 
	int fd;
	struct client * next;
};

struct afp_server;
struct afp_volume;

struct libafpclient {
        int (*unmount_volume) (struct afp_volume * volume);
	void (*log_for_client)(struct client * c,
        	enum loglevels loglevel, int logtype, char *message, ...);
	void (*forced_ending_hook)(void);
	int (*scan_extra_fds)(int command_fd,fd_set *set, int * max_fd);
} ;

extern struct libafpclient * libafpclient;

void client_setup(struct libafpclient * tmpclient);


void signal_main_thread(void);

#endif

