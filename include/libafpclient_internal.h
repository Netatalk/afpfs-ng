
#ifndef __CLIENT_H_
#define __CLIENT_H_

#define MAX_CLIENT_RESPONSE 2048


/* FIXME This should be moved into fuse/ */
struct afp_server_response {
        char result;
        unsigned int len;
};

enum loglevels {
        AFPFSD,
};


struct client {
	char incoming_string[1024];
	int incoming_size;
	char client_string[sizeof(struct afp_server_response) + MAX_CLIENT_RESPONSE];
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
	void (*add_client)(int fd);
	void (*signal_main_thread)(void);
	int (*scan_extra_fds)(int command_fd,fd_set *set, int * max_fd);
} ;

extern struct libafpclient libafpclient;

void client_init(void);

void signal_main_thread(void);

#endif

