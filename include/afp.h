
#ifndef _AFP_H_
#define _AFP_H_

#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <pwd.h>
#include <afp_protocol.h>
#include <libafpclient_internal.h>
#include <sys/statvfs.h>

#define FUSE_USE_VERSION 25

#define AFPFS_VERSION "0.4.3"
#define AFP_UAM_LENGTH 24

#define AFP_MAX_SUPPORTED_VERSION 32


/* These are based on what's in netatalk's */

struct afp_versions {
    char        *av_name;
    int         av_number;
};
extern struct afp_versions afp_versions[];

#define LARGEST_AFP2_FILE_SIZE (4^32)

/* From netatalk's adouble.h */
#define AD_DATE_DELTA         946684800
#define AD_DATE_FROM_UNIX(x)  (htonl((x) - AD_DATE_DELTA))
#define AD_DATE_TO_UNIX(x)    (ntohl(x) + AD_DATE_DELTA)


#define SERVER_MAX_VERSIONS 10
#define SERVER_MAX_UAMS 10

struct afp_rx_buffer {
	unsigned int size;
	unsigned int maxsize;
	char * data;
	int errorcode;
};


struct afp_file_info {
	unsigned short attributes;
	unsigned int did;
	unsigned int creation_date;
	unsigned int modification_date;
	unsigned int backup_date;
	unsigned int fileid;
	unsigned short offspring;
	char sync;
	char finderinfo[32];
	char name[AFP_MAX_PATH];
	char basename[AFP_MAX_PATH];
	char translated_name[AFP_MAX_PATH];
	struct afp_unixprivs unixprivs;
	unsigned int accessrights;
	struct afp_file_info * next;
	unsigned char isdir;
	unsigned long long size;
	unsigned short resourcesize;
	unsigned int resource;
	unsigned short forkid;
	struct afp_icon * icon;
} ;


#define VOLUME_OPTION_APPLEDOUBLE 1

#define VOLUME_EXTRA_FLAGS_VOL_CHMOD_KNOWN 0x1
#define VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN 0x2

#define AFP_VOLUME_UNMOUNTED 0
#define AFP_VOLUME_MOUNTED 1
#define AFP_VOLUME_UNMOUNTING 2

struct afp_volume {
	char flags;
	unsigned short volid;
	unsigned short attributes;
	unsigned short signature;
	unsigned int creation_date;
	unsigned int modification_date;
	unsigned int backup_date;
	struct statvfs stat;
	unsigned char valid_data;
	unsigned char mounted;
	char mountpoint[255];
	struct afp_server * server;
	char name[AFP_VOLUME_NAME_LEN];
	unsigned int options;
	unsigned short dtrefnum;
	char volpassword[AFP_VOLPASS_LEN];
	int mount_errno;
	unsigned int extra_flags;

	/* Our directory ID cache */
	struct did_cache_entry * did_cache_base;
	pthread_mutex_t did_cache_mutex;

	/* Used to trigger startup */
        pthread_cond_t  startup_condition_cond;

	struct {
		uint64_t hits;
		uint64_t misses;
		uint64_t expired;
		uint64_t force_removed;
	} did_cache_stats;

	void * private;  /* This is a private structure for fuse/cmdline, etc */
	pthread_t thread; /* This is the per-volume thread */

	int mapping;

};

int testit(struct afp_volume * volume);

#define SERVER_STATE_CONNECTED 1
#define SERVER_STATE_DISCONNECTED 2
#define SERVER_STATE_DISCONNECTING 3
#define SERVER_STATE_SUSPENDED 4

enum server_type{
	AFPFS_SERVER_TYPE_UNKNOWN,
	AFPFS_SERVER_TYPE_NETATALK,
};


struct afp_server {

	/* Our buffer sizes */
	unsigned int tx_quantum;
	unsigned int rx_quantum;

	unsigned int tx_delay;

	/* Connection information */
	struct sockaddr_in address;
	int fd;

	/* Some stats, for information only */
	struct {
		uint64_t runt_packets;
		uint64_t incoming_dsi;
		uint64_t rx_bytes;
		uint64_t tx_bytes;
		uint64_t requests_pending;
	} stats;

	struct afp_server_mount_request * req;

	/* General information */
	char server_name[AFP_SERVER_NAME_LEN];
	char server_name_utf8[AFP_SERVER_NAME_UTF8_LEN];
        char server_name_precomposed[AFP_SERVER_NAME_UTF8_LEN];
	char machine_type[17];
	char icon[256];
	char signature[16];
	unsigned short flags;
	int connect_state;
	enum server_type server_type;


	/* UAMs */
	unsigned int supported_uams;
	unsigned int using_uam;

	/* Authentication */
	char username[AFP_MAX_USERNAME_LEN];
	char password[AFP_MAX_PASSWORD_LEN];

	/* Versions */
	unsigned char requested_version;
	unsigned char versions[SERVER_MAX_VERSIONS];
	struct afp_versions *using_version;

	/* Volumes */
	unsigned char num_volumes;
	struct afp_volume * volumes;

	void * dsi;
	unsigned int exit_flag;

	/* Our DSI request queue */
	pthread_mutex_t requestid_mutex;
	pthread_mutex_t request_queue_mutex;
	unsigned short lastrequestid;
	unsigned short expectedrequestid;
	struct dsi_request * command_requests;


	char loginmesg[200];
	char servermesg[200];
	char path_encoding;
	unsigned char wait;
	char loggedin;

	/* This is the data for the incoming buffer */
	char * incoming_buffer;
	int data_read;
	int bufsize;

	/* And this is for the outgoing queue */
	pthread_mutex_t send_mutex;

	/* This is for user mapping */
	struct passwd passwd;
	unsigned int server_uid, server_gid;
	int server_gid_valid;

	struct afp_server *next;

	/* These are for DSI attention packets */
	unsigned int attention_quantum;
	unsigned int attention_len;
	char * attention_buffer;

};

struct afp_extattr_info {
	unsigned int maxsize;
	unsigned int size;
	char data[1024];
};
struct afp_comment {
	unsigned int maxsize;
	unsigned int size;
	char *data;
};

struct afp_icon {
	unsigned int maxsize;
	unsigned int size;
	char *data;
};

#define AFP_RESOURCE_TYPE_NONE 0
#define AFP_RESOURCE_TYPE_PARENT1 1
#define AFP_RESOURCE_TYPE_PARENT2 2
#define AFP_RESOURCE_TYPE_COMMENT 3
#define AFP_RESOURCE_TYPE_FINDERINFO 4
#define AFP_RESOURCE_TYPE_RESOURCE 5


#define AFP_DEFAULT_ATTENTION_QUANTUM 1024


int init_uams(void) ;

char * get_uam_names_list(void);

unsigned int default_uams_mask(void);

struct afp_connection_request {
        unsigned char requested_version;
        unsigned int uam_mask;
        char username[AFP_MAX_USERNAME_LEN];
        char password[AFP_MAX_PASSWORD_LEN];
        char hostname[255];
        unsigned int port;
};

struct afp_server * afp_server_full_connect(struct client *c, struct afp_connection_request * req);


void afp_server_disconnect(struct afp_server *s);

struct afp_versions * pick_version(unsigned char *versions,
	unsigned char requested) ;
int pick_uam(unsigned int u1, unsigned int u2);


int afp_dologin(struct afp_server *server,
	unsigned int uam, char * username, char * passwd);

void free_server(struct afp_server *server);

struct afp_server * afp_server_init(struct sockaddr_in * address);


void afp_server_disconnect(struct afp_server *s);
int afp_server_destroy(struct afp_server *s) ;
int afp_server_reconnect(struct afp_server * s, char * mesg,
        unsigned int *l, unsigned int max);
int afp_server_connect(struct afp_server *s, int full);

struct afp_server * afp_server_complete_connection(
	struct client * c,
	struct afp_server * server,
	struct sockaddr_in * address, unsigned char * versions,
	unsigned int uams, char * username, char * password,
	unsigned int requested_version, unsigned int uam_mask);

int afp_connect_volume(struct afp_volume * volume, struct afp_server * server,
	char * mesg, unsigned int * l, unsigned int max);
int something_is_mounted(struct afp_server * server);




int parse_reply_block(struct afp_server *server, char * buf, 
	unsigned int size, unsigned char isdir, 
	unsigned int filebitmap, unsigned int dirbitmap,
        struct afp_file_info * filecur);


int afp_blank_reply(struct afp_server *server, char * buf, unsigned int size, void * ignored);
int add_cache_entry(struct afp_file_info * file) ;
struct afp_file_info * get_cache_by_name(char * name);
int afp_reply(unsigned short subcommand, struct afp_server * server, void * other);
struct afp_server * find_server_by_address(struct sockaddr_in * address);
struct afp_server * find_server_by_signature(char * signature);
struct afp_server * find_server_by_name(char * name);
int server_still_valid(struct afp_server * server);


void add_server(struct afp_server *newserver);
struct afp_server * get_server_base(void);
int afp_server_remove(struct afp_server * server);

int afp_unmount_volume(struct afp_volume * volume);


#define volume_is_readonly(x) ((x)->attributes&kReadOnly)


/* Desktop items */

int afp_opendt(struct afp_volume *volume, unsigned short * refnum);

int afp_opendt_reply(struct afp_server *server, char * buf, unsigned int size, void * other);

int afp_getcomment(struct afp_volume *volume, unsigned int did,
        char * pathname, struct afp_comment * comment);

int afp_getcomment_reply(struct afp_server *server, char * buf, unsigned int size, void * other);
int afp_addcomment(struct afp_volume *volume, unsigned int did,
        char * pathname, char * comment,uint64_t *size);

int afp_geticon_reply(struct afp_server *server, char * buf, unsigned int size, void * other);

int afp_geticon(struct afp_volume * volume, unsigned int filecreator,
        unsigned int filetype, unsigned char icontype, 
	unsigned short length, struct afp_icon * icon);


/* Things you want to do to a server */

int afp_getsrvrmsg(struct afp_server *server, unsigned short messagetype,unsigned char utf8, unsigned char block, char * mesg);

int afp_login_reply(struct afp_server *server, char *buf, unsigned int size,
	struct afp_rx_buffer *other);
int afp_login(struct afp_server *server, char * uaname,
        char * userauthinfo, unsigned int userauthinfo_len,
	struct afp_rx_buffer *rx);
int afp_logincont(struct afp_server *server, unsigned short id,
        char * userauthinfo, unsigned int userauthinfo_len,
	struct afp_rx_buffer *rx);

int afp_getsrvrparms(struct afp_server *server);
int afp_getsrvrparms_reply(struct afp_server *server, char * msg, unsigned int size, void * other);
int afp_getsrvrmsg_reply(struct afp_server *server, char *buf, unsigned int size, void * other);
int afp_logout(struct afp_server *server,unsigned char wait);

int afp_mapname_request(struct afp_server * server, unsigned char subfunction,
        char * name, unsigned int * id);
int afp_mapname_reply(struct afp_server *server, char * buf, unsigned int size, void *other);

int afp_mapid_request(struct afp_server * server, unsigned char subfunction,
	unsigned int id, char *name);

int afp_mapid_reply(struct afp_server *server, char * buf, unsigned int size, void *other);

int afp_getuserinfo_request(struct afp_server * server, int thisuser,
	unsigned int userid, unsigned short bitmap, 
	unsigned int *newuid, unsigned int *newgid);

int afp_getuserinfo_reply(struct afp_server *server, char * buf, unsigned int size, void *other);

int afp_zzzzz(struct afp_server *server);


/* Things you want to do to a volume */

int afp_volopen(struct afp_volume * volume, 
		unsigned short bitmap, char * password);
int afp_volopen_reply(struct afp_server *server, char * buf, unsigned int size, void * ignored);

int afp_getfiledirparms(struct afp_volume *volume, unsigned int did, unsigned int filebitmap, unsigned int dirbitmap, char * pathname,
	struct afp_file_info *fp);

int afp_getfiledirparms_reply(struct afp_server *server, char * buf, unsigned int size, void * other);

int afp_enumerateext2_request(struct afp_volume * volume, 
	unsigned int dirid, 
	unsigned int filebitmap, unsigned int dirbitmap, 
        unsigned short reqcount,
        unsigned long startindex,
        char * path,
	struct afp_file_info ** file_p);

int afp_enumerateext2_reply(struct afp_server *server, char * buf, unsigned int size, void ** other);

int afp_getvolparms_reply(struct afp_server *server, char * buf, unsigned int size,void * other);

int afp_openfork(struct afp_volume * volume,
        unsigned char forktype,
        unsigned int dirid,
        unsigned short accessmode,
        char * filename, 
	struct afp_file_info *fp);

int afp_openfork_reply(struct afp_server *server, char * buf, unsigned int size, void * x);

int afp_readext(struct afp_volume * volume, unsigned short forkid,
                uint64_t offset,
                uint64_t count, struct afp_rx_buffer * rx);

int afp_getvolparms(struct afp_volume * volume, unsigned short bitmap);


int afp_createdir_request(struct afp_volume * volume, unsigned int dirid, const char * pathname, unsigned int *did_p);

int afp_createdir_reply(struct afp_server * server, char * buf, unsigned int len, void * dir_p);

int afp_delete(struct afp_volume * volume,
        unsigned int dirid, char * pathname);

int afp_readext_reply(struct afp_server *server, char * buf, unsigned int size, struct afp_rx_buffer * rx);

int afp_createfile(struct afp_volume * volume, unsigned char flag,
        unsigned int did, char * pathname);

int afp_writeext(struct afp_volume * volume, unsigned short forkid,
        uint64_t offset, uint64_t reqcount,
        char * data, uint64_t * written);


int afp_writeext_reply(struct afp_server *server, char * buf, unsigned int size, uint64_t * written);

int afp_flushfork(struct afp_volume * volume, unsigned short forkid);

int afp_closefork(struct afp_volume * volume, unsigned short forkid);
int afp_setfileparms(struct afp_volume * volume,
        unsigned int dirid, const char * pathname, unsigned short bitmap,
        struct afp_file_info *fp);
int afp_setfiledirparms(struct afp_volume * volume, 
        unsigned int dirid, const char * pathname, unsigned short bitmap,
        struct afp_file_info *fp);

int afp_setdirparms(struct afp_volume * volume,
        unsigned int dirid, const char * pathname, unsigned short bitmap,
        struct afp_file_info *fp);

int afp_volclose(struct afp_volume * volume);


int afp_setforkparms(struct afp_volume *volume,
        unsigned short forkid, unsigned short bitmap, unsigned long len);

int afp_byterangelockext(struct afp_volume * volume,
        unsigned char flag,
        unsigned short forkid,
        uint64_t offset,
        uint64_t len, uint64_t *generated_offset);

int afp_byterangelockext_reply(struct afp_server *server, char * buf, unsigned int size, void * x);


int afp_moveandrename_request(struct afp_volume *volume,
	unsigned int src_did,
	unsigned int dst_did,
	char * src_path, char * dst_path, char *new_name);

int afp_rename_request(struct afp_volume * volume,
        unsigned int dirid,
        char * path_from, char * path_to);

int afp_listextattr(struct afp_volume * volume,
        unsigned int dirid, unsigned short bitmap,
        char * pathname, struct afp_extattr_info * info);

int afp_listextattrs_reply(struct afp_server *server, char * buf, unsigned int size, void * x);



#endif
