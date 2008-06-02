#ifndef __AFPSL_H_
#define __AFPSL_H_
#include <afp.h>

struct afpfsd_connect {
	int fd;
	unsigned int len;
	char data[MAX_CLIENT_RESPONSE+200];
	void (*print) (const char * text);
	char * shmem;
};

typedef uint64_t serverid_t;
typedef uint64_t volumeid_t;


void afp_sl_conn_setup(struct afpfsd_connect * conn);

int afp_sl_exit(struct afpfsd_connect * conn);
int afp_sl_status(struct afpfsd_connect * conn, 
	const char * volumename, const char * servername,
	char * text, unsigned int * remaining);
int afp_sl_resume(struct afpfsd_connect * conn, const char * servername);
int afp_sl_suspend(struct afpfsd_connect * conn, const char * servername);
int afp_sl_unmount(struct afpfsd_connect * conn, const char * volumename);
int afp_sl_connect(struct afpfsd_connect * conn, 
	struct afp_url * url, unsigned int uam_mask,
	serverid_t *id);
int afp_sl_getvolid(struct afpfsd_connect * conn,
        struct afp_url * url, volumeid_t *volid);

int afp_sl_mount(struct afpfsd_connect * conn, 
	struct afp_url * url, const char * mountpoint, 
	const char * map, unsigned int volume_options);

int afp_sl_attach(struct afpfsd_connect * conn, 
	struct afp_url * url, unsigned int volume_options);
int afp_sl_detach(struct afpfsd_connect * conn, volumeid_t * volumeid,
	struct afp_url * url);

int afp_sl_readdir(struct afpfsd_connect * conn,
        volumeid_t * volid, const char * path, struct afp_url * url,
	int start, int count, unsigned int * numfiles, char ** data,
	int * eod);

int afp_sl_getvols(struct afpfsd_connect * conn,
	struct afp_url * url, unsigned int start,
	unsigned int count, unsigned int * numvols,
	char * data);

int afp_sl_stat(struct afpfsd_connect * conn, 
	volumeid_t * volid, const char * path,
	struct afp_url * url, struct stat * stat);


int afp_sl_setup(struct afpfsd_connect * conn);
int afp_sl_setup_diffuser(struct afpfsd_connect * conn,
	unsigned int uid, unsigned int gid);



#endif
