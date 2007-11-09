#ifndef __AFP_REPLIES_H_
#define __AFP_REPLIES_H_

int parse_reply_block(struct afp_server *server, char * buf,
	unsigned int size, unsigned char isdir,
	unsigned int filebitmap, unsigned int dirbitmap,
	struct afp_file_info * filecur);

int afp_blank_reply(struct afp_server *server, char * buf, unsigned int size, void * ignored);

int afp_reply(unsigned short subcommand, struct afp_server * server, void * other);

int afp_opendt_reply(struct afp_server *server, char * buf, unsigned int size, void * other);

int afp_getcomment_reply(struct afp_server *server, char * buf, unsigned int size, void * other);

int afp_geticon_reply(struct afp_server *server, char * buf, unsigned int size, void * other);

int afp_login_reply(struct afp_server *server, char *buf, unsigned int size,
	struct afp_rx_buffer *other);

int afp_getsessiontoken_reply(struct afp_server *server, char *buf,
	unsigned int size, struct afp_token * token);

int afp_getsrvrparms_reply(struct afp_server *server, char * msg, unsigned int size, void * other);

int afp_getsrvrmsg_reply(struct afp_server *server, char *buf, unsigned int size, void * other);

int afp_mapname_reply(struct afp_server *server, char * buf, unsigned int size, void *other);

int afp_mapid_reply(struct afp_server *server, char * buf, unsigned int size, void *other);

int afp_getuserinfo_reply(struct afp_server *server, char * buf, unsigned int size, void *other);

int afp_volopen_reply(struct afp_server *server, char * buf, unsigned int size, void * ignored);

int afp_getfiledirparms_reply(struct afp_server *server, char * buf, unsigned int size, void * other);

int afp_enumerate_reply(struct afp_server *server, char * buf, unsigned int size, void ** other);

int afp_enumerateext2_reply(struct afp_server *server, char * buf, unsigned int size, void ** other);

int afp_getvolparms_reply(struct afp_server *server, char * buf, unsigned int size,void * other);

int afp_openfork_reply(struct afp_server *server, char * buf, unsigned int size, void * x);

int afp_createdir_reply(struct afp_server * server, char * buf, unsigned int len, void * dir_p);

int afp_read_reply(struct afp_server *server, char * buf, unsigned int size, struct afp_rx_buffer * rx);

int afp_readext_reply(struct afp_server *server, char * buf, unsigned int size, struct afp_rx_buffer * rx);

int afp_write_reply(struct afp_server *server, char * buf, unsigned int size, uint32_t * written);

int afp_writeext_reply(struct afp_server *server, char * buf, unsigned int size, uint64_t * written);

int afp_byterangelock_reply(struct afp_server *server, char * buf, unsigned int size, void * x);

int afp_byterangelockext_reply(struct afp_server *server, char * buf, unsigned int size, void * x);

int afp_listextattrs_reply(struct afp_server *server, char * buf, unsigned int size, void * x);

#endif
