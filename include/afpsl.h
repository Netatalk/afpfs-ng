#ifndef __AFPSL_H_
#define __AFPSL_H_
#include <afp.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "errno.h"

struct afp_volume_summary
{
	char volume_name_printable[AFP_VOLUME_NAME_UTF8_LEN];
	char flags;
};

typedef void *  serverid_t;
typedef void *  volumeid_t;


void afp_sl_conn_setup(void);

int afp_sl_exit(void);
int afp_sl_status(const char * volumename, const char * servername,
	char * text, unsigned int * remaining);
int afp_sl_resume(const char * servername);
int afp_sl_suspend(const char * servername);
int afp_sl_unmount(const char * volumename);

int afp_sl_connect(struct afp_url * url, unsigned int uam_mask,
	serverid_t *id, char * loginmesg, int * error);

int afp_sl_getvolid(struct afp_url * url, volumeid_t *volid);

int afp_sl_mount(struct afp_url * url, const char * mountpoint, 
	const char * map, unsigned int volume_options);

int afp_sl_attach(struct afp_url * url, unsigned int volume_options,
	volumeid_t * volumeid);

int afp_sl_detach(volumeid_t * volumeid,
	struct afp_url * url);

int afp_sl_readdir(volumeid_t * volid, const char * path, struct afp_url * url,
	int start, int count, unsigned int * numfiles, 
	struct afp_file_info_basic ** fpb,
	int * eod);

int afp_sl_getvols(struct afp_url * url, unsigned int start,
	unsigned int count, unsigned int * numvols,
	struct afp_volume_summary * vols);

int afp_sl_stat(volumeid_t * volid, const char * path,
	struct afp_url * url, struct stat * stat);

int afp_sl_open(volumeid_t * volid, const char * path,
	struct afp_url * url,unsigned int *fileid,
	unsigned int mode);

int afp_sl_read(volumeid_t * volid, unsigned int fileid, unsigned int resource, 
	unsigned long long start,
        unsigned int length, unsigned int * received,
        unsigned int * eof, char * data);

	
int afp_sl_close(volumeid_t * volid, unsigned int fileid);

int afp_sl_serverinfo(struct afp_url * url, struct afp_server_basic * basic);

int afp_sl_get_mountpoint(struct afp_url * url, char * mountpoint);

int afp_sl_setup(void);
int afp_sl_setup_diffuser(unsigned int uid, unsigned int gid);
#ifdef __cplusplus
}
#endif




#endif
