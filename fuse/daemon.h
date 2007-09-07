#ifndef __DAEMON_H_
#define __DAEMON_H_


void add_fd_and_signal(int fd);
void rm_fd_and_signal(int fd);
void signal_main_thread(void);


int add_client(int fd);
int process_client_fds(fd_set * set, int max_fd, int ** onfd);

#endif
