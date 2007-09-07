
#ifndef __DSI_PROTOCOL_H_
#define __DSI_PROTOCOL_H_


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

void dsi_setup_header(struct afp_server * server, struct dsi_header * header, char command);


#endif
