
#ifndef __DSI_H_
#define __DSI_H_

#include "afp.h"

struct dsi_request
{
	unsigned short requestid;
	unsigned char subcommand;
	void * other;
	unsigned char wait;
	pthread_cond_t  condition_cond;
	pthread_mutex_t condition_mutex;
	struct dsi_request * next;
	int return_code;
};

struct dsi_header {
	uint8_t flags;
	uint8_t command;
	uint16_t requestid;
	union {
		int error_code;
		unsigned int data_offset;
	} return_code;
	uint32_t length;
	uint32_t reserved;
};


int dsi_receive(struct afp_server * server, void * data, int size);
int dsi_getstatus(struct afp_server * server);

int dsi_opensession(struct afp_server *server);

int dsi_send(struct afp_server *server, char * msg, int size,int wait,unsigned char subcommand, void ** other);
struct dsi_session * dsi_create(struct afp_server *server);
int dsi_restart(struct afp_server *server);
int dsi_recv(struct afp_server * server);

void dsi_setup_header(struct afp_server * server, struct dsi_header * header, char command);


#endif
