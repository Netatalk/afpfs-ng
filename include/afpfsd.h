#ifndef _AFPFSD_H_
#define _AFPFSD_H_

#include <limits.h>

#include "afpsl.h"

#define SERVER_FILENAME "/tmp/afp_server"

#define AFP_SERVER_COMMAND_MOUNT 1
#define AFP_SERVER_COMMAND_ATTACH 2
#define AFP_SERVER_COMMAND_DETACH 3
#define AFP_SERVER_COMMAND_STATUS 4
#define AFP_SERVER_COMMAND_UNMOUNT 6
#define AFP_SERVER_COMMAND_SUSPEND 8
#define AFP_SERVER_COMMAND_RESUME 9
#define AFP_SERVER_COMMAND_PING 11
#define AFP_SERVER_COMMAND_EXIT 12
#define AFP_SERVER_COMMAND_CONNECT 14
#define AFP_SERVER_COMMAND_GETVOLID 16
#define AFP_SERVER_COMMAND_READDIR 19
#define AFP_SERVER_COMMAND_GETVOLS 20
#define AFP_SERVER_COMMAND_STAT 21
#define AFP_SERVER_COMMAND_OPEN 22
#define AFP_SERVER_COMMAND_READ 23
#define AFP_SERVER_COMMAND_CLOSE 24
#define AFP_SERVER_COMMAND_SERVERINFO 25
#define AFP_SERVER_COMMAND_GET_MOUNTPOINT 26

/* File I/O commands for stateless API */
#define AFP_SERVER_COMMAND_WRITE 27
#define AFP_SERVER_COMMAND_FLUSH 28
#define AFP_SERVER_COMMAND_CREATE 29
#define AFP_SERVER_COMMAND_TRUNCATE 30
#define AFP_SERVER_COMMAND_FTRUNCATE 31

/* Metadata commands for stateless API */
#define AFP_SERVER_COMMAND_MKDIR 32
#define AFP_SERVER_COMMAND_RMDIR 33
#define AFP_SERVER_COMMAND_UNLINK 34
#define AFP_SERVER_COMMAND_RENAME 35
#define AFP_SERVER_COMMAND_SYMLINK 36
#define AFP_SERVER_COMMAND_READLINK 37
#define AFP_SERVER_COMMAND_CHMOD 38
#define AFP_SERVER_COMMAND_CHOWN 39
#define AFP_SERVER_COMMAND_UTIME 40
#define AFP_SERVER_COMMAND_SETXATTR 41
#define AFP_SERVER_COMMAND_REMOVEXATTR 42
#define AFP_SERVER_COMMAND_LISTXATTR 43
#define AFP_SERVER_COMMAND_GETXATTR 44
#define AFP_SERVER_COMMAND_MKNOD 45
#define AFP_SERVER_COMMAND_STATFS 46

/* Internal command for manager daemon - not in stateless API */
#define AFP_SERVER_COMMAND_SPAWN_MOUNT 100

#define AFP_SERVER_RESULT_OKAY 0
#define AFP_SERVER_RESULT_ERROR 1
#define AFP_SERVER_RESULT_TRYING 2
#define AFP_SERVER_RESULT_WARNING 3
#define AFP_SERVER_RESULT_ENOENT 4
#define AFP_SERVER_RESULT_NOTCONNECTED 5
#define AFP_SERVER_RESULT_NOTATTACHED 6
#define AFP_SERVER_RESULT_ALREADY_CONNECTED 7
#define AFP_SERVER_RESULT_ALREADY_ATTACHED 8
#define AFP_SERVER_RESULT_NOAUTHENT 9

#define AFP_SERVER_RESULT_ERROR_UNKNOWN 10


#define AFP_SERVER_RESULT_NOVOLUME 14
#define AFP_SERVER_RESULT_ALREADY_MOUNTED 15
#define AFP_SERVER_RESULT_VOLPASS_NEEDED 16
#define AFP_SERVER_RESULT_MOUNTPOINT_NOEXIST 17
#define AFP_SERVER_RESULT_NOSERVER 18
#define AFP_SERVER_RESULT_MOUNTPOINT_PERM 19
#define AFP_SERVER_RESULT_TIMEDOUT 20

#define AFP_SERVER_RESULT_AFPFSD_ERROR 21
#define AFP_SERVER_RESULT_NOTSUPPORTED 22


#define AFPFSD_SHMEM_KEY 0x1221
#define AFPFSD_SHMEM_SIZE 8192

struct afp_server_response_header {
    char result;
    unsigned int len;
};

struct afp_server_request_header {
    char command;
    unsigned int len;
    unsigned int close;
};


struct afp_server_resume_request {
    struct afp_server_request_header header;
    char server_name[AFP_SERVER_NAME_LEN];
};

struct afp_server_suspend_request {
    struct afp_server_request_header header;
    char server_name[AFP_SERVER_NAME_LEN];
};

struct afp_server_unmount_request {
    struct afp_server_request_header header;
    char name[PATH_MAX];
};

struct afp_server_unmount_response {
    struct afp_server_response_header header;
    char unmount_message[1024];
};

struct afp_server_mount_request {
    struct afp_server_request_header header;
    struct afp_url url;
    unsigned int uam_mask;
    char mountpoint[255];
    unsigned int volume_options;
    unsigned int map;
    int changeuid;
    char fuse_options[256];
};

struct afp_server_mount_response {
    struct afp_server_response_header header;
    volumeid_t volumeid;
};

struct afp_server_attach_request {
    struct afp_server_request_header header;
    struct afp_url url;
    unsigned int volume_options;
};

struct afp_server_attach_response {
    struct afp_server_response_header header;
    volumeid_t volumeid;
};

struct afp_server_detach_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
};

struct afp_server_detach_response {
    struct afp_server_response_header header;
    char detach_message[1024];
};

struct afp_server_status_request {
    struct afp_server_request_header header;
    char volumename[AFP_VOLUME_NAME_UTF8_LEN];
    char servername[AFP_SERVER_NAME_LEN];
};

struct afp_server_status_response {
    struct afp_server_response_header header;
};

struct afp_server_getvolid_request {
    struct afp_server_request_header header;
    struct afp_url url;
};

struct afp_server_getvolid_response {
    struct afp_server_response_header header;
    volumeid_t volumeid;
};

struct afp_server_connect_request {
    struct afp_server_request_header header;
    struct afp_url url;
    unsigned int uam_mask;
};

struct afp_server_connect_response {
    struct afp_server_response_header header;
    serverid_t serverid;
    char loginmesg[AFP_LOGINMESG_LEN];
    int connect_error;
};

struct afp_server_readdir_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    int start;
    int count;
};

struct afp_server_readdir_response {
    struct afp_server_response_header header;
    unsigned int numfiles;
    char eod;
};

struct afp_server_exit_request {
    struct afp_server_request_header header;
};

struct afp_server_getvols_request {
    struct afp_server_request_header header;
    struct afp_url url;
    int start;
    int count;
};

struct afp_server_getvols_response {
    struct afp_server_response_header header;
    unsigned int num;
    char endlist;
};

struct afp_server_stat_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_stat_response {
    struct afp_server_response_header header;
    struct stat stat;
};

struct afp_server_open_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    int mode;
};

struct afp_server_open_response {
    struct afp_server_response_header header;
    unsigned int fileid;
};

struct afp_server_read_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    unsigned int fileid;
    unsigned long long start;
    unsigned int length;
    unsigned int resource;
    char shm_name[32];              /* POSIX shm name, empty = inline data in response */
};

struct afp_server_read_response {
    struct afp_server_response_header header;
    unsigned int received;
    unsigned int eof;
};

struct afp_server_close_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    unsigned int fileid;
};

struct afp_server_close_response {
    struct afp_server_response_header header;
};

struct afp_server_serverinfo_request {
    struct afp_server_request_header header;
    struct afp_url url;
};

struct afp_server_serverinfo_response {
    struct afp_server_response_header header;
    struct afp_server_basic server_basic;
};

struct afp_server_get_mountpoint_request {
    struct afp_server_request_header header;
    struct afp_url url;
};

struct afp_server_get_mountpoint_response {
    struct afp_server_response_header header;
    char mountpoint[PATH_MAX];
};

/* Internal command for manager daemon - not in stateless API */
struct afp_server_spawn_mount_request {
    struct afp_server_request_header header;
    char mountpoint[255];
    char socket_id[PATH_MAX];
};

/* Generic response structure for simple responses */
struct afp_server_response {
    char result;
    unsigned int len;
};

/*
 * Stateless API request/response structures
 */

/* Write command - writes data to an open file */
struct afp_server_write_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    unsigned int fileid;
    unsigned long long offset;
    unsigned int length;
    unsigned int resource;          /* 0 = data fork, 1 = resource fork */
    char shm_name[32];              /* POSIX shm name, empty = inline data follows */
    /* If shm_name is empty, data follows immediately after this struct */
};

struct afp_server_write_response {
    struct afp_server_response_header header;
    unsigned int written;
};

/* Flush command - flushes pending writes to server */
struct afp_server_flush_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    unsigned int fileid;
};

struct afp_server_flush_response {
    struct afp_server_response_header header;
};

/* Create command - creates and opens a new file */
struct afp_server_create_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    int mode;                       /* O_RDONLY, O_WRONLY, O_RDWR, etc. */
    unsigned int permissions;       /* Unix permissions for new file */
};

struct afp_server_create_response {
    struct afp_server_response_header header;
    unsigned int fileid;
};

/* Truncate command - truncates file by path */
struct afp_server_truncate_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    unsigned long long size;
};

struct afp_server_truncate_response {
    struct afp_server_response_header header;
};

/* Ftruncate command - truncates file by fileid */
struct afp_server_ftruncate_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    unsigned int fileid;
    unsigned long long size;
};

struct afp_server_ftruncate_response {
    struct afp_server_response_header header;
};

/* Mkdir command - creates a directory */
struct afp_server_mkdir_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    unsigned int mode;
};

struct afp_server_mkdir_response {
    struct afp_server_response_header header;
};

/* Rmdir command - removes a directory */
struct afp_server_rmdir_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_rmdir_response {
    struct afp_server_response_header header;
};

/* Unlink command - removes a file */
struct afp_server_unlink_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_unlink_response {
    struct afp_server_response_header header;
};

/* Rename command - renames/moves a file or directory */
struct afp_server_rename_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char from_path[AFP_MAX_PATH];
    char to_path[AFP_MAX_PATH];
};

struct afp_server_rename_response {
    struct afp_server_response_header header;
};

/* Symlink command - creates a symbolic link */
struct afp_server_symlink_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char target[AFP_MAX_PATH];      /* Link target */
    char linkpath[AFP_MAX_PATH];    /* Path of the symlink to create */
};

struct afp_server_symlink_response {
    struct afp_server_response_header header;
};

/* Readlink command - reads a symbolic link */
struct afp_server_readlink_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_readlink_response {
    struct afp_server_response_header header;
    char target[AFP_MAX_PATH];
};

/* Chmod command - changes file permissions */
struct afp_server_chmod_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    unsigned int mode;
};

struct afp_server_chmod_response {
    struct afp_server_response_header header;
};

/* Chown command - changes file ownership */
struct afp_server_chown_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    unsigned int uid;
    unsigned int gid;
};

struct afp_server_chown_response {
    struct afp_server_response_header header;
};

/* Utime command - changes file timestamps */
struct afp_server_utime_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    long atime_sec;
    long atime_nsec;
    long mtime_sec;
    long mtime_nsec;
};

struct afp_server_utime_response {
    struct afp_server_response_header header;
};

/* Setxattr command - sets an extended attribute */
struct afp_server_setxattr_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    char name[256];                 /* Attribute name */
    unsigned int size;              /* Size of value data */
    int flags;                      /* XATTR_CREATE, XATTR_REPLACE, etc. */
    /* Value data follows immediately after this struct */
};

struct afp_server_setxattr_response {
    struct afp_server_response_header header;
};

/* Removexattr command - removes an extended attribute */
struct afp_server_removexattr_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    char name[256];
};

struct afp_server_removexattr_response {
    struct afp_server_response_header header;
};

/* Listxattr command - lists extended attributes */
struct afp_server_listxattr_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    unsigned int size;              /* Buffer size, 0 = query size only */
};

struct afp_server_listxattr_response {
    struct afp_server_response_header header;
    unsigned int size;              /* Actual size of list */
    /* List data follows immediately after this struct */
};

/* Getxattr command - gets an extended attribute */
struct afp_server_getxattr_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    char name[256];
    unsigned int size;              /* Buffer size, 0 = query size only */
};

struct afp_server_getxattr_response {
    struct afp_server_response_header header;
    unsigned int size;              /* Actual size of value */
    /* Value data follows immediately after this struct */
};

/* Mknod command - creates a special file */
struct afp_server_mknod_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    unsigned int mode;
    unsigned int dev;               /* Device number (for device files) */
};

struct afp_server_mknod_response {
    struct afp_server_response_header header;
};

/* Statfs command - gets filesystem statistics */
struct afp_server_statfs_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_statfs_response {
    struct afp_server_response_header header;
    unsigned long long blocks;      /* Total blocks */
    unsigned long long bfree;       /* Free blocks */
    unsigned long long bavail;      /* Available blocks (non-root) */
    unsigned long long files;       /* Total inodes */
    unsigned long long ffree;       /* Free inodes */
    unsigned int bsize;             /* Block size */
    unsigned int namelen;           /* Max filename length */
};

#endif
