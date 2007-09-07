#ifndef __COMMANDS_H_
#define __COMMANDS_H_

void fuse_log_for_client(struct client * c,
        enum loglevels loglevel, int logtype, char *message, ...) ;

int fuse_process_client_fds(fd_set * set, int max_fd, int ** onfd);
int fuse_add_client(int fd);



#endif
