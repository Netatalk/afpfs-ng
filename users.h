#ifndef __USERS_H_
#define __USERS_H_


void user_deleteall(struct afp_server * server);
int user_findbyhostid(struct afp_server * server, unsigned int hostid, 
	unsigned int *serverid);
void user_add(struct afp_server * server,
	unsigned int hostid,unsigned int serverid);

#endif
