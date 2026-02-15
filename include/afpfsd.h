#ifndef _AFP_SERVER_H_
#define _AFP_SERVER_H_

#include <limits.h>
#include "afpsl.h"

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
#define AFP_SERVER_COMMAND_WRITE 27
#define AFP_SERVER_COMMAND_CREAT 28
#define AFP_SERVER_COMMAND_CHMOD 29
#define AFP_SERVER_COMMAND_RENAME 30
#define AFP_SERVER_COMMAND_UNLINK 31
#define AFP_SERVER_COMMAND_TRUNCATE 32
#define AFP_SERVER_COMMAND_MKDIR 33
#define AFP_SERVER_COMMAND_RMDIR 34
#define AFP_SERVER_COMMAND_STATFS 35
#define AFP_SERVER_COMMAND_UTIME 36
#define AFP_SERVER_COMMAND_DISCONNECT 37
#define AFP_SERVER_COMMAND_CHANGEPW 38

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

#define AFP_SERVER_RESULT_DAEMON_ERROR 21
#define AFP_SERVER_RESULT_NOTSUPPORTED 22
#define AFP_SERVER_RESULT_ACCESS 23
#define AFP_SERVER_RESULT_EXIST 24

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
    char mountpoint[AFP_MOUNTPOINT_LEN];
};

struct afp_server_suspend_request {
    struct afp_server_request_header header;
    char mountpoint[AFP_MOUNTPOINT_LEN];
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
    char mountpoint[AFP_MOUNTPOINT_LEN];
    unsigned int volume_options;
    unsigned int map;
    int changeuid;
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
    char mountpoint[AFP_MOUNTPOINT_LEN];
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

struct afp_server_write_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    unsigned int fileid;
    unsigned long long offset;
    unsigned int size;
    unsigned int resource;
};

struct afp_server_write_response {
    struct afp_server_response_header header;
    unsigned int written;
};

struct afp_server_creat_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    mode_t mode;
};

struct afp_server_creat_response {
    struct afp_server_response_header header;
};

struct afp_server_chmod_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    mode_t mode;
};

struct afp_server_chmod_response {
    struct afp_server_response_header header;
};

struct afp_server_rename_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path_from[AFP_MAX_PATH];
    char path_to[AFP_MAX_PATH];
};

struct afp_server_rename_response {
    struct afp_server_response_header header;
};

struct afp_server_unlink_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_unlink_response {
    struct afp_server_response_header header;
};

struct afp_server_truncate_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    unsigned long long offset;
};

struct afp_server_truncate_response {
    struct afp_server_response_header header;
};

struct afp_server_utime_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    struct utimbuf times;
};

struct afp_server_utime_response {
    struct afp_server_response_header header;
};

struct afp_server_mkdir_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
    mode_t mode;
};

struct afp_server_mkdir_response {
    struct afp_server_response_header header;
};

struct afp_server_rmdir_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_rmdir_response {
    struct afp_server_response_header header;
};

struct afp_server_statfs_request {
    struct afp_server_request_header header;
    volumeid_t volumeid;
    char path[AFP_MAX_PATH];
};

struct afp_server_statfs_response {
    struct afp_server_response_header header;
    struct statvfs stat;
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

struct afp_server_disconnect_request {
    struct afp_server_request_header header;
    serverid_t serverid;
};

struct afp_server_disconnect_response {
    struct afp_server_response_header header;
};

struct afp_server_changepw_request {
    struct afp_server_request_header header;
    struct afp_url url;
    char oldpasswd[AFP_MAX_PASSWORD_LEN];
    char newpasswd[AFP_MAX_PASSWORD_LEN];
};

struct afp_server_changepw_response {
    struct afp_server_response_header header;
    int afp_error;
};

#endif
