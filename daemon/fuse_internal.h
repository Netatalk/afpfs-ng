#ifndef __FUSE_INTERNAL_H_
#define __FUSE_INTERNAL_H_

#define AFP_CLIENT_INCOMING_BUF 8192


struct fuse_client {
	char incoming_string[AFP_CLIENT_INCOMING_BUF];
	int incoming_size;
	char outgoing_string[1000 + MAX_CLIENT_RESPONSE];
	int fd;
	int lock;
	struct fuse_client * next;
	char * shmem;
	int toremove;
	int pending;
};

#define client_string_len(x) \
	(strlen(((struct fuse_client *)(x))->outgoing_string))
#endif
