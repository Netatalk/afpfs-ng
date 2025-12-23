#ifndef __AFPSL_H_
#define __AFPSL_H_

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "afp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stateless AFP client library (libafpsl)
 *
 * This library provides a stateless IPC interface to the afpfsd daemon.
 * All AFP protocol state is managed by the daemon; the client only needs
 * to track volumeid_t and fileid handles.
 *
 * Usage:
 *   1. Call afp_sl_setup() to connect to the daemon
 *   2. Use afp_sl_mount() or afp_sl_attach() to access a volume
 *   3. Use file I/O and metadata functions with the volumeid
 *   4. Call afp_sl_unmount() or afp_sl_detach() when done
 */

struct afp_volume_summary {
    char volume_name_printable[AFP_VOLUME_NAME_UTF8_LEN];
    char flags;
};

/* Opaque handle types */
typedef void   *serverid_t;
typedef void   *volumeid_t;

/*
 * Connection setup
 */
int afp_sl_setup(void);
int afp_sl_setup_diffuser(unsigned int uid, unsigned int gid);

/*
 * Session management
 */
int afp_sl_exit(void);
int afp_sl_status(const char *volumename, const char *servername,
                  char *text, unsigned int *remaining);
int afp_sl_resume(const char *servername);
int afp_sl_suspend(const char *servername);

/*
 * Server connection
 */
int afp_sl_connect(struct afp_url *url, unsigned int uam_mask,
                   serverid_t *id, char *loginmesg, int *error);
int afp_sl_serverinfo(struct afp_url *url, struct afp_server_basic *basic);

/*
 * Volume operations
 */
int afp_sl_mount(struct afp_url *url, const char *mountpoint,
                 const char *map, unsigned int volume_options);
int afp_sl_unmount(const char *mountpoint);
int afp_sl_attach(struct afp_url *url, unsigned int volume_options,
                  volumeid_t *volumeid);
int afp_sl_detach(volumeid_t *volumeid);
int afp_sl_getvolid(struct afp_url *url, volumeid_t *volid);
int afp_sl_getvols(struct afp_url *url, unsigned int start,
                   unsigned int count, unsigned int *numvols,
                   struct afp_volume_summary *vols);
int afp_sl_get_mountpoint(struct afp_url *url, char *mountpoint);

/*
 * File I/O operations
 */
int afp_sl_open(volumeid_t *volid, const char *path, int mode,
                unsigned int *fileid);
int afp_sl_create(volumeid_t *volid, const char *path, int mode,
                  unsigned int permissions, unsigned int *fileid);
int afp_sl_read(volumeid_t *volid, unsigned int fileid, unsigned int resource,
                unsigned long long offset, unsigned int length,
                unsigned int *received, int *eof, char *data);
int afp_sl_write(volumeid_t *volid, unsigned int fileid, unsigned int resource,
                 unsigned long long offset, unsigned int length,
                 const char *data, unsigned int *written);
int afp_sl_flush(volumeid_t *volid, unsigned int fileid);
int afp_sl_close(volumeid_t *volid, unsigned int fileid);

/*
 * Metadata operations (path-based)
 */
int afp_sl_stat(volumeid_t *volid, const char *path, struct stat *stbuf);
int afp_sl_readdir(volumeid_t *volid, const char *path,
                   int start, int count, unsigned int *numfiles,
                   struct afp_file_info_basic **fpb, int *eod);
int afp_sl_mkdir(volumeid_t *volid, const char *path, unsigned int mode);
int afp_sl_rmdir(volumeid_t *volid, const char *path);
int afp_sl_unlink(volumeid_t *volid, const char *path);
int afp_sl_rename(volumeid_t *volid, const char *from, const char *to);
int afp_sl_symlink(volumeid_t *volid, const char *target, const char *linkpath);
int afp_sl_readlink(volumeid_t *volid, const char *path, char *buf, size_t size);
int afp_sl_chmod(volumeid_t *volid, const char *path, unsigned int mode);
int afp_sl_chown(volumeid_t *volid, const char *path, unsigned int uid,
                 unsigned int gid);
int afp_sl_utime(volumeid_t *volid, const char *path, long atime_sec,
                 long atime_nsec, long mtime_sec, long mtime_nsec);
int afp_sl_truncate(volumeid_t *volid, const char *path,
                    unsigned long long size);
int afp_sl_ftruncate(volumeid_t *volid, unsigned int fileid,
                     unsigned long long size);

/*
 * Filesystem operations
 */
int afp_sl_statfs(volumeid_t *volid, const char *path,
                  unsigned long long *blocks, unsigned long long *bfree,
                  unsigned long long *bavail, unsigned long long *files,
                  unsigned long long *ffree, unsigned int *bsize,
                  unsigned int *namelen);

/*
 * Extended attributes (AFP 3.2+)
 */
int afp_sl_getxattr(volumeid_t *volid, const char *path, const char *name,
                    void *value, size_t size, int *actual_size);
int afp_sl_setxattr(volumeid_t *volid, const char *path, const char *name,
                    const void *value, size_t size, int flags);
int afp_sl_listxattr(volumeid_t *volid, const char *path,
                     char *list, size_t size, int *actual_size);
int afp_sl_removexattr(volumeid_t *volid, const char *path, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* __AFPSL_H_ */
