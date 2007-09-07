#ifndef __CLIENT_URL_H_
#define __CLIENT_URL_H_

struct afp_url {
	char username[AFP_MAX_USERNAME_LEN];
	char password[AFP_MAX_PASSWORD_LEN];
	char volpassword[AFP_VOLPASS_LEN];
	char volume[AFP_VOLUME_NAME_LEN];
	char hostname[AFP_HOSTNAME_LEN];
	char path[AFP_MAX_PATH];
	unsigned int port;
};

void default_url(struct afp_url *url);
int parse_url(struct afp_url * url, char * toparse);
#endif 
