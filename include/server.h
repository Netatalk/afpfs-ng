#ifndef __SERVER_H_
#define __SERVER_H_
struct afp_server * connect_to_new_server(
	struct client * c, 
	struct sockaddr_in *address,
	unsigned char requested_version, 
	char * username, char * password);


struct afp_server * new_server(
        struct client * c,
        struct sockaddr_in * address, unsigned char * versions,
                unsigned int uams, char * username, char * password,
                unsigned int requested_version, unsigned int uam_mask);

int get_address(struct client * c, const char * hostname, unsigned int port,                struct sockaddr_in * address);

int server_login(struct client * c, struct afp_server * server);


#endif
