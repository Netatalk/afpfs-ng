#ifndef _AFP_SERVER_H_
#define _AFP_SERVER_H_

#include "afp_protocol.h"

#define SERVER_FILENAME "/tmp/afp_server"

#define AFP_SERVER_COMMAND_MOUNT 1
#define AFP_SERVER_COMMAND_STATUS 2
#define AFP_SERVER_COMMAND_UNMOUNT 3
#define AFP_SERVER_COMMAND_SUSPEND 4
#define AFP_SERVER_COMMAND_RESUME 5
#define AFP_SERVER_COMMAND_EXIT 6
#define AFP_SERVER_COMMAND_CONNECT 7
#define AFP_SERVER_COMMAND_EXTRA_STATUS 7

#define AFP_SERVER_RESULT_OKAY 1
#define AFP_SERVER_RESULT_ERROR 2
#define AFP_SERVER_RESULT_TRYING 3
#define AFP_SERVER_RESULT_WARNING 4
#define AFP_SERVER_RESULT_NOTFOUND 5

#define MAX_CLIENT_RESPONSE 2048

#define AFP_SERVER_STATUS_HEADER 0x1
#define AFP_SERVER_STATUS_VOLUME 0x2
#define AFP_SERVER_STATUS_OVERVIEW 0x4
#define AFP_SERVER_STATUS_VOLDETAILS 0x8
#define AFP_SERVER_STATUS_EVERYTHING 0xf

#define AFP_SERVER_STATUS_SEARCHEVERYTHING 0
#define AFP_SERVER_STATUS_BYSERVERNAME 1
#define AFP_SERVER_STATUS_BYHOSTNAME 2
#define AFP_SERVER_STATUS_BYSIGNATURE 3
#define AFP_SERVER_STATUS_BYVOLUMENAME 4

struct afp_server_response {
	char result;
	unsigned int len;
};

struct afp_server_resume_request {
	char server_name[AFP_SERVER_NAME_LEN];
};

struct afp_server_suspend_request {
	char server_name[AFP_SERVER_NAME_LEN];
};

struct afp_server_unmount_request {
	char mountpoint[255];
};

struct afp_server_mount_request {
	unsigned char requested_version;
	unsigned int uam_mask;
        char username[AFP_MAX_USERNAME_LEN];
        char password[AFP_MAX_PASSWORD_LEN];
        char volpassword[9];
	char volume[31];
	char hostname[AFP_HOSTNAME_LEN];
	char mountpoint[255];
	unsigned int volume_options;
	unsigned int port;
};

struct afp_server_search {
	char volumename[AFP_VOLUME_NAME_LEN];
	char hostname[AFP_HOSTNAME_LEN];
	char signature[AFP_SIGNATURE_LEN];
	char servername[AFP_SERVER_NAME_LEN];
	unsigned int searchby;
};

struct afp_server_status_request {
	unsigned int flags;
	struct afp_server_search search;
};

struct afp_server_extra_status_request {
	struct afp_server_search search;
};

struct afp_server_connect_request {
	unsigned char requested_version;
	unsigned int uam_mask;
        char username[AFP_MAX_USERNAME_LEN];
        char password[AFP_MAX_PASSWORD_LEN];
	char hostname[AFP_HOSTNAME_LEN];
	unsigned int volume_options;
	unsigned int port;
};


#endif
