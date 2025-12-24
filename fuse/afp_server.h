#ifndef _AFP_SERVER_H_
#define _AFP_SERVER_H_

#include <limits.h>

#define SERVER_FILENAME "/tmp/afp_server"

/*
 * IMPORTANT: These command/result codes MUST match include/afpfsd.h exactly.
 * They define the IPC protocol between mount_afpfs/afp_client and afpfsd.
 *
 * Note: This header uses simplified structures (no header field) for backward
 * compatibility with the existing FUSE client implementation. The constants
 * must stay synchronized with afpfsd.h.
 */
#define AFP_SERVER_COMMAND_MOUNT 1
#define AFP_SERVER_COMMAND_STATUS 4
#define AFP_SERVER_COMMAND_UNMOUNT 6
#define AFP_SERVER_COMMAND_SUSPEND 8
#define AFP_SERVER_COMMAND_RESUME 9
#define AFP_SERVER_COMMAND_PING 11
#define AFP_SERVER_COMMAND_EXIT 12

/* Internal command for manager daemon - not in afpfsd.h */
#define AFP_SERVER_COMMAND_SPAWN_MOUNT 100

#define AFP_SERVER_RESULT_OKAY 0
#define AFP_SERVER_RESULT_ERROR 1
#define AFP_SERVER_RESULT_TRYING 2
#define AFP_SERVER_RESULT_WARNING 3

struct afp_server_resume_request {
    char mountpoint[AFP_MOUNTPOINT_LEN];
};

struct afp_server_suspend_request {
    char mountpoint[AFP_MOUNTPOINT_LEN];
};

struct afp_server_unmount_request {
    char mountpoint[AFP_MOUNTPOINT_LEN];
};

struct afp_server_mount_request {
    struct afp_url url;
    unsigned int uam_mask;
    char mountpoint[AFP_MOUNTPOINT_LEN];
    unsigned int volume_options;
    unsigned int map;
    int changeuid;
    char fuse_options[256];
};

struct afp_server_status_request {
    char volumename[AFP_VOLUME_NAME_LEN];
    char servername[AFP_VOLUME_NAME_LEN];
    char mountpoint[AFP_MOUNTPOINT_LEN];
};

struct afp_server_spawn_mount_request {
    char mountpoint[AFP_MOUNTPOINT_LEN];
    char socket_id[PATH_MAX];
};

struct afp_server_response {
    char result;
    unsigned int len;
};



#endif
