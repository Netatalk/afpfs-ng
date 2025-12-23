/*
 * stateless.c - Stateless AFP client library (libafpsl)
 *
 * Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
 * Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>
 *
 * This library provides a stateless IPC interface to the afpfsd daemon.
 * All AFP protocol state is managed by the daemon; the client only needs
 * to track volumeid_t and fileid handles.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "afp.h"
#include "afpfsd.h"
#include "afpsl.h"
#include "map_def.h"

/* Global connection state */
static int daemon_fd = -1;
static unsigned int target_uid = 0;
static unsigned int target_gid = 0;
static int use_alternate_uid = 0;

/* Buffer for responses */
#define RESPONSE_BUF_SIZE (MAX_CLIENT_RESPONSE + 4096)
static char response_buffer[RESPONSE_BUF_SIZE];

/*
 * Internal: Connect to the afpfsd daemon
 */
static int daemon_connect(void)
{
    int sock;
    struct sockaddr_un servaddr;
    char filename[PATH_MAX];
    unsigned int uid;

    if (daemon_fd >= 0) {
        return 0;  /* Already connected */
    }

    uid = use_alternate_uid ? target_uid : geteuid();

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        return -errno;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    snprintf(filename, sizeof(filename), "%s-%u", SERVER_FILENAME, uid);

    if (strlcpy(servaddr.sun_path, filename,
                sizeof(servaddr.sun_path)) >= sizeof(servaddr.sun_path)) {
        close(sock);
        return -ENAMETOOLONG;
    }

    if (connect(sock, (struct sockaddr *)&servaddr,
                sizeof(servaddr.sun_family) + strlen(servaddr.sun_path) + 1) < 0) {
        close(sock);
        return -errno;
    }

    daemon_fd = sock;
    return 0;
}

/*
 * Internal: Close daemon connection (for reconnection)
 */
static void daemon_disconnect(void)
{
    if (daemon_fd >= 0) {
        close(daemon_fd);
        daemon_fd = -1;
    }
}

/*
 * Internal: Send a request and read the response
 * Each IPC operation opens a new connection since the daemon
 * closes connections after handling each command.
 */
static int send_request(const void *req, size_t req_len,
                        void *resp, size_t resp_len)
{
    ssize_t n;
    size_t total = 0;
    int ret;

    /* Always reconnect for each request since daemon closes after each command */
    daemon_disconnect();
    ret = daemon_connect();
    if (ret < 0) {
        return ret;
    }

    /* Send request */
    n = write(daemon_fd, req, req_len);
    if (n < 0) {
        daemon_disconnect();
        return -errno;
    }
    if ((size_t)n != req_len) {
        daemon_disconnect();
        return -EIO;
    }

    /* Read response header first */
    while (total < resp_len) {
        n = read(daemon_fd, (char *)resp + total, resp_len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            daemon_disconnect();
            return -errno;
        }
        if (n == 0) {
            daemon_disconnect();
            return -ECONNRESET;
        }
        total += n;

        /* Check if we have the header and can determine full length */
        if (total >= sizeof(struct afp_server_response_header)) {
            struct afp_server_response_header *hdr = resp;
            if (total >= hdr->len || total >= resp_len) {
                break;
            }
        }
    }

    /* Keep connection for potential additional data reads */
    return ((struct afp_server_response_header *)resp)->result;
}

/*
 * Internal: Send request with extra data (for write, setxattr, etc.)
 */
static int send_request_with_data(const void *req, size_t req_len,
                                  const void *data, size_t data_len,
                                  void *resp, size_t resp_len)
{
    struct iovec iov[2];
    ssize_t n;
    size_t total = 0;
    int ret;

    /* Always reconnect for each request */
    daemon_disconnect();
    ret = daemon_connect();
    if (ret < 0) {
        return ret;
    }

    /* Send request + data using writev */
    iov[0].iov_base = (void *)req;
    iov[0].iov_len = req_len;
    iov[1].iov_base = (void *)data;
    iov[1].iov_len = data_len;

    n = writev(daemon_fd, iov, 2);
    if (n < 0) {
        daemon_disconnect();
        return -errno;
    }
    if ((size_t)n != req_len + data_len) {
        daemon_disconnect();
        return -EIO;
    }

    /* Read response */
    while (total < resp_len) {
        n = read(daemon_fd, (char *)resp + total, resp_len - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            daemon_disconnect();
            return -errno;
        }
        if (n == 0) {
            daemon_disconnect();
            return -ECONNRESET;
        }
        total += n;

        if (total >= sizeof(struct afp_server_response_header)) {
            struct afp_server_response_header *hdr = resp;
            if (total >= hdr->len || total >= resp_len) {
                break;
            }
        }
    }

    return ((struct afp_server_response_header *)resp)->result;
}

/*
 * Connection setup
 *
 * Note: We don't maintain a persistent connection. Each IPC request
 * opens a new connection since the daemon closes after each command.
 * This function just verifies we can reach the daemon.
 */
int afp_sl_setup(void)
{
    int ret;

    use_alternate_uid = 0;

    /* Test connection to daemon, then close it.
     * send_request() will open a fresh connection for each command. */
    ret = daemon_connect();
    if (ret == 0) {
        daemon_disconnect();
    }
    return ret;
}

int afp_sl_setup_diffuser(unsigned int uid, unsigned int gid)
{
    target_uid = uid;
    target_gid = gid;
    use_alternate_uid = 1;

    /* Close existing connection if any */
    if (daemon_fd >= 0) {
        close(daemon_fd);
        daemon_fd = -1;
    }

    return daemon_connect();
}

/*
 * Session management
 */
int afp_sl_exit(void)
{
    struct afp_server_exit_request req;
    struct afp_server_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_EXIT;
    req.header.len = sizeof(req);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_status(const char *volumename, const char *servername,
                  char *text, unsigned int *remaining)
{
    struct afp_server_status_request req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_STATUS;
    req.header.len = sizeof(req);

    if (volumename) {
        snprintf(req.volumename, sizeof(req.volumename), "%s", volumename);
    }
    if (servername) {
        snprintf(req.servername, sizeof(req.servername), "%s", servername);
    }

    ret = send_request(&req, sizeof(req), response_buffer, RESPONSE_BUF_SIZE);

    if (ret == AFP_SERVER_RESULT_OKAY && text && remaining) {
        struct afp_server_response_header *hdr =
            (struct afp_server_response_header *)response_buffer;
        size_t text_len = hdr->len - sizeof(*hdr);
        if (text_len > *remaining) {
            text_len = *remaining;
        }
        memcpy(text, response_buffer + sizeof(*hdr), text_len);
        *remaining -= text_len;
    }

    return ret;
}

int afp_sl_resume(const char *servername)
{
    struct afp_server_resume_request req;
    struct afp_server_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_RESUME;
    req.header.len = sizeof(req);
    snprintf(req.server_name, sizeof(req.server_name), "%s", servername);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_suspend(const char *servername)
{
    struct afp_server_suspend_request req;
    struct afp_server_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_SUSPEND;
    req.header.len = sizeof(req);
    snprintf(req.server_name, sizeof(req.server_name), "%s", servername);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

/*
 * Server connection
 */
int afp_sl_connect(struct afp_url *url, unsigned int uam_mask,
                   serverid_t *id, char *loginmesg, int *error)
{
    struct afp_server_connect_request req;
    struct afp_server_connect_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_CONNECT;
    req.header.len = sizeof(req);
    memcpy(&req.url, url, sizeof(req.url));
    req.uam_mask = uam_mask;

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY) {
        if (id) {
            *id = resp.serverid;
        }
        if (loginmesg) {
            snprintf(loginmesg, AFP_LOGINMESG_LEN, "%s", resp.loginmesg);
        }
    }
    if (error) {
        *error = resp.connect_error;
    }

    return ret;
}

int afp_sl_serverinfo(struct afp_url *url, struct afp_server_basic *basic)
{
    struct afp_server_serverinfo_request req;
    struct afp_server_serverinfo_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_SERVERINFO;
    req.header.len = sizeof(req);
    memcpy(&req.url, url, sizeof(req.url));

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && basic) {
        memcpy(basic, &resp.server_basic, sizeof(*basic));
    }

    return ret;
}

/*
 * Volume operations
 */
int afp_sl_mount(struct afp_url *url, const char *mountpoint,
                 const char *map, unsigned int volume_options)
{
    struct afp_server_mount_request req;
    struct afp_server_mount_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_MOUNT;
    req.header.len = sizeof(req);
    memcpy(&req.url, url, sizeof(req.url));
    snprintf(req.mountpoint, sizeof(req.mountpoint), "%s", mountpoint);

    if (map) {
        req.map = map_string_to_num(map);
    } else {
        req.map = AFP_MAPPING_UNKNOWN;
    }

    req.volume_options = volume_options;
    req.changeuid = use_alternate_uid;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_unmount(const char *mountpoint)
{
    struct afp_server_unmount_request req;
    struct afp_server_unmount_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_UNMOUNT;
    req.header.len = sizeof(req);
    snprintf(req.name, sizeof(req.name), "%s", mountpoint);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_attach(struct afp_url *url, unsigned int volume_options,
                  volumeid_t *volumeid)
{
    struct afp_server_attach_request req;
    struct afp_server_attach_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_ATTACH;
    req.header.len = sizeof(req);
    memcpy(&req.url, url, sizeof(req.url));
    req.volume_options = volume_options;

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && volumeid) {
        *volumeid = resp.volumeid;
    }

    return ret;
}

int afp_sl_detach(volumeid_t *volumeid)
{
    struct afp_server_detach_request req;
    struct afp_server_detach_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_DETACH;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volumeid, sizeof(req.volumeid));

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_getvolid(struct afp_url *url, volumeid_t *volid)
{
    struct afp_server_getvolid_request req;
    struct afp_server_getvolid_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_GETVOLID;
    req.header.len = sizeof(req);
    memcpy(&req.url, url, sizeof(req.url));

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && volid) {
        *volid = resp.volumeid;
    }

    return ret;
}

int afp_sl_getvols(struct afp_url *url, unsigned int start,
                   unsigned int count, unsigned int *numvols,
                   struct afp_volume_summary *vols)
{
    struct afp_server_getvols_request req;
    struct afp_server_getvols_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_GETVOLS;
    req.header.len = sizeof(req);
    memcpy(&req.url, url, sizeof(req.url));
    req.start = start;
    req.count = count;

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && numvols) {
        *numvols = resp.num;
    }

    /* Volume data would follow the response - not implemented yet */
    (void)vols;

    return ret;
}

int afp_sl_get_mountpoint(struct afp_url *url, char *mountpoint)
{
    struct afp_server_get_mountpoint_request req;
    struct afp_server_get_mountpoint_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_GET_MOUNTPOINT;
    req.header.len = sizeof(req);
    memcpy(&req.url, url, sizeof(req.url));

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && mountpoint) {
        snprintf(mountpoint, PATH_MAX, "%s", resp.mountpoint);
    }

    return ret;
}

/*
 * File I/O operations
 */
int afp_sl_open(volumeid_t *volid, const char *path, int mode,
                unsigned int *fileid)
{
    struct afp_server_open_request req;
    struct afp_server_open_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_OPEN;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.mode = mode;

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && fileid) {
        *fileid = resp.fileid;
    }

    return ret;
}

int afp_sl_create(volumeid_t *volid, const char *path, int mode,
                  unsigned int permissions, unsigned int *fileid)
{
    struct afp_server_create_request req;
    struct afp_server_create_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_CREATE;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.mode = mode;
    req.permissions = permissions;

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && fileid) {
        *fileid = resp.fileid;
    }

    return ret;
}

int afp_sl_read(volumeid_t *volid, unsigned int fileid, unsigned int resource,
                unsigned long long offset, unsigned int length,
                unsigned int *received, int *eof, char *data)
{
    struct afp_server_read_request req;
    int ret;
    size_t resp_size = sizeof(struct afp_server_read_response) + length;
    char *resp_buf;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_READ;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    req.fileid = fileid;
    req.start = offset;
    req.length = length;
    req.resource = resource;

    resp_buf = malloc(resp_size);
    if (!resp_buf) {
        return -ENOMEM;
    }

    ret = send_request(&req, sizeof(req), resp_buf, resp_size);

    if (ret == AFP_SERVER_RESULT_OKAY) {
        struct afp_server_read_response *resp =
            (struct afp_server_read_response *)resp_buf;
        if (received) {
            *received = resp->received;
        }
        if (eof) {
            *eof = resp->eof;
        }
        if (data && resp->received > 0) {
            memcpy(data, resp_buf + sizeof(*resp), resp->received);
        }
    }

    free(resp_buf);
    return ret;
}

int afp_sl_write(volumeid_t *volid, unsigned int fileid, unsigned int resource,
                 unsigned long long offset, unsigned int length,
                 const char *data, unsigned int *written)
{
    struct afp_server_write_request req;
    struct afp_server_write_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_WRITE;
    req.header.len = sizeof(req) + length;
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    req.fileid = fileid;
    req.offset = offset;
    req.length = length;
    req.resource = resource;

    ret = send_request_with_data(&req, sizeof(req), data, length,
                                  &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && written) {
        *written = resp.written;
    }

    return ret;
}

int afp_sl_flush(volumeid_t *volid, unsigned int fileid)
{
    struct afp_server_flush_request req;
    struct afp_server_flush_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_FLUSH;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    req.fileid = fileid;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_close(volumeid_t *volid, unsigned int fileid)
{
    struct afp_server_close_request req;
    struct afp_server_close_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_CLOSE;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    req.fileid = fileid;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

/*
 * Metadata operations
 */
int afp_sl_stat(volumeid_t *volid, const char *path, struct stat *stbuf)
{
    struct afp_server_stat_request req;
    struct afp_server_stat_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_STAT;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && stbuf) {
        memcpy(stbuf, &resp.stat, sizeof(*stbuf));
    }

    return ret;
}

int afp_sl_readdir(volumeid_t *volid, const char *path,
                   int start, int count, unsigned int *numfiles,
                   struct afp_file_info_basic **fpb, int *eod)
{
    struct afp_server_readdir_request req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_READDIR;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.start = start;
    req.count = count;

    ret = send_request(&req, sizeof(req), response_buffer, RESPONSE_BUF_SIZE);

    if (ret == AFP_SERVER_RESULT_OKAY) {
        struct afp_server_readdir_response *resp =
            (struct afp_server_readdir_response *)response_buffer;

        if (numfiles) {
            *numfiles = resp->numfiles;
        }
        if (eod) {
            *eod = resp->eod;
        }
        if (fpb && resp->numfiles > 0) {
            size_t data_size = resp->numfiles * sizeof(struct afp_file_info_basic);
            *fpb = malloc(data_size);
            if (*fpb) {
                memcpy(*fpb, response_buffer + sizeof(*resp), data_size);
            }
        }
    }

    return ret;
}

int afp_sl_mkdir(volumeid_t *volid, const char *path, unsigned int mode)
{
    struct afp_server_mkdir_request req;
    struct afp_server_mkdir_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_MKDIR;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.mode = mode;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_rmdir(volumeid_t *volid, const char *path)
{
    struct afp_server_rmdir_request req;
    struct afp_server_rmdir_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_RMDIR;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_unlink(volumeid_t *volid, const char *path)
{
    struct afp_server_unlink_request req;
    struct afp_server_unlink_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_UNLINK;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_rename(volumeid_t *volid, const char *from, const char *to)
{
    struct afp_server_rename_request req;
    struct afp_server_rename_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_RENAME;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.from_path, sizeof(req.from_path), "%s", from);
    snprintf(req.to_path, sizeof(req.to_path), "%s", to);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_symlink(volumeid_t *volid, const char *target, const char *linkpath)
{
    struct afp_server_symlink_request req;
    struct afp_server_symlink_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_SYMLINK;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.target, sizeof(req.target), "%s", target);
    snprintf(req.linkpath, sizeof(req.linkpath), "%s", linkpath);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_readlink(volumeid_t *volid, const char *path, char *buf, size_t size)
{
    struct afp_server_readlink_request req;
    struct afp_server_readlink_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_READLINK;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY && buf) {
        snprintf(buf, size, "%s", resp.target);
    }

    return ret;
}

int afp_sl_chmod(volumeid_t *volid, const char *path, unsigned int mode)
{
    struct afp_server_chmod_request req;
    struct afp_server_chmod_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_CHMOD;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.mode = mode;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_chown(volumeid_t *volid, const char *path, unsigned int uid,
                 unsigned int gid)
{
    struct afp_server_chown_request req;
    struct afp_server_chown_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_CHOWN;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.uid = uid;
    req.gid = gid;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_utime(volumeid_t *volid, const char *path, long atime_sec,
                 long atime_nsec, long mtime_sec, long mtime_nsec)
{
    struct afp_server_utime_request req;
    struct afp_server_utime_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_UTIME;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.atime_sec = atime_sec;
    req.atime_nsec = atime_nsec;
    req.mtime_sec = mtime_sec;
    req.mtime_nsec = mtime_nsec;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_truncate(volumeid_t *volid, const char *path,
                    unsigned long long size)
{
    struct afp_server_truncate_request req;
    struct afp_server_truncate_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_TRUNCATE;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.size = size;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

int afp_sl_ftruncate(volumeid_t *volid, unsigned int fileid,
                     unsigned long long size)
{
    struct afp_server_ftruncate_request req;
    struct afp_server_ftruncate_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_FTRUNCATE;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    req.fileid = fileid;
    req.size = size;

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}

/*
 * Filesystem operations
 */
int afp_sl_statfs(volumeid_t *volid, const char *path,
                  unsigned long long *blocks, unsigned long long *bfree,
                  unsigned long long *bavail, unsigned long long *files,
                  unsigned long long *ffree, unsigned int *bsize,
                  unsigned int *namelen)
{
    struct afp_server_statfs_request req;
    struct afp_server_statfs_response resp;
    int ret;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_STATFS;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);

    ret = send_request(&req, sizeof(req), &resp, sizeof(resp));

    if (ret == AFP_SERVER_RESULT_OKAY) {
        if (blocks) *blocks = resp.blocks;
        if (bfree) *bfree = resp.bfree;
        if (bavail) *bavail = resp.bavail;
        if (files) *files = resp.files;
        if (ffree) *ffree = resp.ffree;
        if (bsize) *bsize = resp.bsize;
        if (namelen) *namelen = resp.namelen;
    }

    return ret;
}

/*
 * Extended attributes
 */
int afp_sl_getxattr(volumeid_t *volid, const char *path, const char *name,
                    void *value, size_t size, int *actual_size)
{
    struct afp_server_getxattr_request req;
    int ret;
    size_t resp_size = sizeof(struct afp_server_getxattr_response) + size;
    char *resp_buf;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_GETXATTR;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    snprintf(req.name, sizeof(req.name), "%s", name);
    req.size = size;

    resp_buf = malloc(resp_size);
    if (!resp_buf) {
        return -ENOMEM;
    }

    ret = send_request(&req, sizeof(req), resp_buf, resp_size);

    if (ret == AFP_SERVER_RESULT_OKAY) {
        struct afp_server_getxattr_response *resp =
            (struct afp_server_getxattr_response *)resp_buf;
        if (actual_size) {
            *actual_size = resp->size;
        }
        if (value && resp->size > 0 && size > 0) {
            size_t copy_size = resp->size < size ? resp->size : size;
            memcpy(value, resp_buf + sizeof(*resp), copy_size);
        }
    }

    free(resp_buf);
    return ret;
}

int afp_sl_setxattr(volumeid_t *volid, const char *path, const char *name,
                    const void *value, size_t size, int flags)
{
    struct afp_server_setxattr_request req;
    struct afp_server_setxattr_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_SETXATTR;
    req.header.len = sizeof(req) + size;
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    snprintf(req.name, sizeof(req.name), "%s", name);
    req.size = size;
    req.flags = flags;

    return send_request_with_data(&req, sizeof(req), value, size,
                                   &resp, sizeof(resp));
}

int afp_sl_listxattr(volumeid_t *volid, const char *path,
                     char *list, size_t size, int *actual_size)
{
    struct afp_server_listxattr_request req;
    int ret;
    size_t resp_size = sizeof(struct afp_server_listxattr_response) + size;
    char *resp_buf;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_LISTXATTR;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    req.size = size;

    resp_buf = malloc(resp_size);
    if (!resp_buf) {
        return -ENOMEM;
    }

    ret = send_request(&req, sizeof(req), resp_buf, resp_size);

    if (ret == AFP_SERVER_RESULT_OKAY) {
        struct afp_server_listxattr_response *resp =
            (struct afp_server_listxattr_response *)resp_buf;
        if (actual_size) {
            *actual_size = resp->size;
        }
        if (list && resp->size > 0 && size > 0) {
            size_t copy_size = resp->size < size ? resp->size : size;
            memcpy(list, resp_buf + sizeof(*resp), copy_size);
        }
    }

    free(resp_buf);
    return ret;
}

int afp_sl_removexattr(volumeid_t *volid, const char *path, const char *name)
{
    struct afp_server_removexattr_request req;
    struct afp_server_removexattr_response resp;

    memset(&req, 0, sizeof(req));
    req.header.command = AFP_SERVER_COMMAND_REMOVEXATTR;
    req.header.len = sizeof(req);
    memcpy(&req.volumeid, volid, sizeof(req.volumeid));
    snprintf(req.path, sizeof(req.path), "%s", path);
    snprintf(req.name, sizeof(req.name), "%s", name);

    return send_request(&req, sizeof(req), &resp, sizeof(resp));
}
