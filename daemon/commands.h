#ifndef __COMMANDS_H_
#define __COMMANDS_H_

#include "daemon_client.h"

int fuse_register_afpclient(void);
void fuse_set_log_method(int new_method);

int process_command(struct daemon_client * c);

struct afp_volume * command_sub_attach_volume(struct daemon_client * c,
	struct afp_server * server, char * volname, char * volpassword,
	int * response_result);

int daemon_scan_extra_fds(int command_fd, fd_set *set,
	fd_set * toset, fd_set *exceptfds, int * max_fd, int err);


#endif
