/*
 *  commands.c
 *
 *  Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <time.h>
#include <stdarg.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fuse.h>

#include "afp.h"
#include "dsi.h"
#include "afpfsd.h"
#include "utils.h"
#include "daemon.h"
#include "uams_def.h"
#include "codepage.h"
#include "libafpclient.h"
#include "map_def.h"
#include "midlevel.h"
#include "fuse_int.h"
#include "fuse_error.h"
#include "fuse_internal.h"

#if defined(__APPLE__)
#define FUSE_DEVICE "/dev/macfuse0"
#else
#define FUSE_DEVICE "/dev/fuse"
#endif

/*
 * Stateless API: Daemon-side file handle table
 *
 * This table maps opaque file IDs (returned to clients) to actual
 * AFP file_info structures. Each handle has its own mutex to serialize
 * concurrent operations on the same file, solving the concurrency issues
 * that plagued the stateful architecture.
 */
struct daemon_file_handle {
    unsigned int fileid;            /* Client-facing opaque ID */
    struct afp_file_info *fp;       /* Actual AFP file info */
    struct afp_volume *volume;      /* Associated volume */
    pthread_mutex_t mutex;          /* Per-file lock for serialization */
    int refcount;                   /* Reference count for concurrent access */
    struct daemon_file_handle *next;
};

static struct daemon_file_handle *file_handle_table = NULL;
static pthread_mutex_t file_handle_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int next_fileid = 1;

/* Allocate a new file handle and add to the table */
static struct daemon_file_handle *allocate_file_handle(
    struct afp_volume *volume, struct afp_file_info *fp)
{
    struct daemon_file_handle *handle;

    handle = malloc(sizeof(struct daemon_file_handle));
    if (!handle) {
        return NULL;
    }

    memset(handle, 0, sizeof(*handle));
    pthread_mutex_init(&handle->mutex, NULL);
    handle->fp = fp;
    handle->volume = volume;
    handle->refcount = 1;

    pthread_mutex_lock(&file_handle_table_mutex);
    handle->fileid = next_fileid++;
    if (next_fileid == 0) {
        next_fileid = 1;  /* Wrap around, skip 0 */
    }
    handle->next = file_handle_table;
    file_handle_table = handle;
    pthread_mutex_unlock(&file_handle_table_mutex);

    return handle;
}

/* Look up a file handle by ID, incrementing refcount */
static struct daemon_file_handle *lookup_file_handle(unsigned int fileid)
{
    struct daemon_file_handle *handle;

    pthread_mutex_lock(&file_handle_table_mutex);
    for (handle = file_handle_table; handle; handle = handle->next) {
        if (handle->fileid == fileid) {
            handle->refcount++;
            pthread_mutex_unlock(&file_handle_table_mutex);
            return handle;
        }
    }
    pthread_mutex_unlock(&file_handle_table_mutex);
    return NULL;
}

/* Release a file handle reference, freeing if refcount reaches zero */
static void release_file_handle(struct daemon_file_handle *handle)
{
    struct daemon_file_handle **curr;
    int should_free = 0;

    pthread_mutex_lock(&file_handle_table_mutex);
    handle->refcount--;
    if (handle->refcount <= 0) {
        /* Remove from list */
        for (curr = &file_handle_table; *curr; curr = &(*curr)->next) {
            if (*curr == handle) {
                *curr = handle->next;
                break;
            }
        }
        should_free = 1;
    }
    pthread_mutex_unlock(&file_handle_table_mutex);

    if (should_free) {
        pthread_mutex_destroy(&handle->mutex);
        free(handle);
    }
}

/* Lock a file handle for exclusive access */
static void lock_file_handle(struct daemon_file_handle *handle)
{
    pthread_mutex_lock(&handle->mutex);
}

/* Unlock a file handle */
static void unlock_file_handle(struct daemon_file_handle *handle)
{
    pthread_mutex_unlock(&handle->mutex);
}

/* Find volume by volumeid (opaque pointer cast) */
static struct afp_volume *find_volume_by_id(volumeid_t volid)
{
    /* volumeid_t is just a void* that we use as a direct pointer */
    return (struct afp_volume *)volid;
}

static int fuse_log_method = LOG_METHOD_SYSLOG;
static int fuse_log_min_rank = 2; /* Default: LOG_NOTICE */

void trigger_exit(void);

static struct fuse_client *client_base = NULL;

static int volopen(struct fuse_client * c, struct afp_volume * volume);
static int process_command(struct fuse_client * c);
static struct afp_volume *mount_volume(struct fuse_client * c,
                                       struct afp_server * server, char *volname, char *volpassword) ;

void fuse_set_log_method(int new_method)
{
    fuse_log_method = new_method;
}

static int loglevel_to_rank(int loglevel)
{
    switch (loglevel) {
    case LOG_DEBUG:
        return 0;

    case LOG_INFO:
        return 1;

    case LOG_NOTICE:
        return 2;

    case LOG_WARNING:
        return 3;

    case LOG_ERR:
        return 4;

    default:
        return 4; /* Treat unknown as error-level to avoid dropping */
    }
}

void fuse_set_log_level(int loglevel)
{
    fuse_log_min_rank = loglevel_to_rank(loglevel);
}


static int remove_client(struct fuse_client * toremove)
{
    struct fuse_client * c, *prev = NULL;

    fprintf(stderr, "remove_client: removing fd=%d\n", toremove ? toremove->fd : -1);

    for (c = client_base; c; c = c->next) {
        if (c == toremove) {
            if (!prev) {
                /* Removing the first element - update head pointer */
                client_base = toremove->next;
                fprintf(stderr, "remove_client: was first, new head=%p (fd=%d)\n",
                        (void *)client_base, client_base ? client_base->fd : -1);
            } else {
                prev->next = toremove->next;
                fprintf(stderr, "remove_client: was not first, prev->next now=%p\n",
                        (void *)prev->next);
            }

            free(toremove);
            toremove = NULL;
            return 0;
        }

        prev = c;
    }

    fprintf(stderr, "remove_client: client not found in list!\n");
    return -1;
}

static int fuse_add_client(int fd)
{
    struct fuse_client * c, *newc;

    fprintf(stderr, "fuse_add_client: adding fd=%d, current client_base=%p\n",
            fd, (void *)client_base);

    if ((newc = malloc(sizeof(*newc))) == NULL) {
        goto error;
    }

    memset(newc, 0, sizeof(*newc));
    newc->fd = fd;
    newc->next = NULL;

    if (client_base == NULL) {
        client_base = newc;
        fprintf(stderr, "fuse_add_client: list was empty, new head=%p\n", (void *)newc);
    } else {
        for (c = client_base; c->next; c = c->next);

        c->next = newc;
        fprintf(stderr, "fuse_add_client: appended to list after fd=%d\n", c->fd);
    }

    return 0;
error:
    return -1;
}

static int fuse_process_client_fds(fd_set * set,
                                   __attribute__((unused)) int max_fd)
{
    struct fuse_client * c;
    int count = 0;

    /* Debug: count clients in list */
    for (c = client_base; c; c = c->next) {
        count++;
    }
    if (count > 0 || get_debug_mode()) {
        fprintf(stderr, "fuse_process_client_fds: %d clients in list\n", count);
    }

    for (c = client_base; c; c = c->next) {
        fprintf(stderr, "fuse_process_client_fds: checking client fd=%d, FD_ISSET=%d\n",
                c->fd, FD_ISSET(c->fd, set) ? 1 : 0);
        if (FD_ISSET(c->fd, set)) {
            if (process_command(c) < 0) {
                return -1;
            }

            return 1;
        }
    }

    return 0;
}

static int fuse_scan_extra_fds(int command_fd, fd_set *set, int * max_fd)
{
    struct sockaddr_un new_addr;
    socklen_t new_len = sizeof(struct sockaddr_un);
    int new_fd = -1;
    int accepted_new = 0;

    if (FD_ISSET(command_fd, set)) {
        new_fd = accept(command_fd, (struct sockaddr *) &new_addr, &new_len);

        if (new_fd >= 0) {
            fuse_add_client(new_fd);
            /* Add to global fd set for next select iteration */
            add_fd_and_signal(new_fd);
            accepted_new = 1;

            if ((new_fd + 1) > *max_fd) {
                *max_fd = new_fd + 1;
            }
        }
    }

    /* Process any client fds that have data ready (from this select call) */
    switch (fuse_process_client_fds(set, *max_fd)) {
    case -1: {
        int i;
        FD_CLR(new_fd, set);

        for (i = *max_fd; i >= 0; i--)
            if (FD_ISSET(i, set)) {
                *max_fd = i;
                break;
            }
    }

    (*max_fd)++;
    close(new_fd);
    return 1;

    case 1:
        return 1;

    case 0:
        /* No client had data ready. If we just accepted a new connection,
         * return success so the main loop iterates and select() can detect
         * data on the new fd. */
        if (accepted_new) {
            return 1;
        }
        break;
    }

    /* No activity at all - this shouldn't normally happen */
    return 0;
}

static void fuse_log_for_client(void * priv,
                                __attribute__((unused)) enum logtypes logtype,
                                int loglevel, const char *message)
{
    int len = 0;
    struct fuse_client * c = priv;
    int type_rank = loglevel_to_rank(loglevel);

    if (type_rank < fuse_log_min_rank) {
        return; /* Filter out less-verbose messages */
    }

    if (c) {
        len = strlen(c->client_string);
        snprintf(c->client_string + len,
                 MAX_CLIENT_RESPONSE - len,
                 "%s", message);
    } else {
        if (fuse_log_method & LOG_METHOD_SYSLOG) {
            syslog(loglevel, "%s", message);
        }

        if (fuse_log_method & LOG_METHOD_STDOUT) {
            printf("%s", message);
        }
    }
}

struct start_fuse_thread_arg {
    struct afp_volume *volume;
    struct fuse_client *client;
    int wait;
    int fuse_result;
    int fuse_errno;
    int changeuid;
    char *fuse_options;
};

/*
 * Remove commas from fsname, as it confuses the fuse option parser.
 * Copied from sshfs.c
 */
static void fsname_remove_commas(char *fsname)
{
    if (strchr(fsname, ',') != NULL) {
        char *s = fsname;
        char *d = s;

        for (; *s; s++) {
            if (*s != ',') {
                *d++ = *s;
            }
        }

        *d = *s;
    }
}

// * Copied from sshfs.c
static char *fsname_escape_commas(char *fsnameold)
{
    char *fsname = malloc(strlen(fsnameold) * 2 + 1);
    char *d = fsname;
    char *s;

    for (s = fsnameold; *s; s++) {
        if (*s == '\\' || *s == ',') {
            *d++ = '\\';
        }

        *d++ = *s;
    }

    *d = '\0';
    free(fsnameold);
    return fsname;
}

static void *start_fuse_thread(void * other)
{
    int fuseargc = 0;
    char *fuseargv[200];
#define mountstring_len (AFP_SERVER_NAME_UTF8_LEN+1+AFP_VOLUME_NAME_UTF8_LEN+1)
    char mountstring[mountstring_len];
#define fsoption_buf_len 1024
    char fsoption_buf[fsoption_buf_len];
#ifdef __APPLE__
#define volname_option_buf_len 256
    char volname_option_buf[volname_option_buf_len];
#endif
    struct start_fuse_thread_arg * arg = other;
    struct afp_volume * volume = arg->volume;
    struct afp_server * server = volume->server;
    char *fsname;
    int libver = fuse_version();
    /* Initialize the entire array to NULL to prevent FUSE 3 from reading garbage */
    memset(fuseargv, 0, sizeof(fuseargv));
    /* Check to see if we have permissions to access the mountpoint */
    snprintf(mountstring, mountstring_len, "%s:%s",
             server->server_name_printable,
             volume->volume_name_printable);
    fuseargc = 0;
    /* argv[0] must be the program name for FUSE */
    fuseargv[0] = "afpfs";
    fuseargc++;

    if (get_debug_mode()) {
        fuseargv[fuseargc] = "-d";
        fuseargc++;
    } else {
        fuseargv[fuseargc] = "-f";
        fuseargc++;
    }

    if (arg->changeuid) {
        fuseargv[fuseargc] = "-o";
        fuseargc++;
        fuseargv[fuseargc] = "allow_other";
        fuseargc++;
    }

    asprintf(&fsname, "%s@%s:%s", server->username, server->server_name,
             volume->volume_name);

    if (libver >= 27) {
        if (libver >= 28) {
            fsname = fsname_escape_commas(fsname);
        } else {
            fsname_remove_commas(fsname);
        }

        snprintf(fsoption_buf, fsoption_buf_len, "-osubtype=afpfs,fsname=%s", fsname);
    } else {
        fsname_remove_commas(fsname);
        snprintf(fsoption_buf, fsoption_buf_len, "-ofsname=afpfs#%s", fsname);
    }

    fuseargv[fuseargc] = fsoption_buf;
    fuseargc++;
#ifdef __APPLE__
    /* Add volname option for macOS to display custom name in Finder */
    snprintf(volname_option_buf, volname_option_buf_len, "-ovolname=%s",
             volume->volume_name_printable);
    fuseargv[fuseargc] = volname_option_buf;
    fuseargc++;
#endif

    if (arg->fuse_options && strlen(arg->fuse_options)) {
        fuseargv[fuseargc] = "-o";
        fuseargc++;
        fuseargv[fuseargc] = arg->fuse_options;
        fuseargc++;
    }

#ifdef USE_SINGLE_THREAD
    fuseargv[fuseargc] = "-s";
    fuseargc++;
#else
    /* On Linux with FUSE 3, cap idle worker threads to avoid libfuse warning about invalid values */
#if !defined(__APPLE__) && FUSE_USE_VERSION >= 30
    fuseargv[fuseargc] = "-o";
    fuseargc++;
    fuseargv[fuseargc] = "max_idle_threads=10";
    fuseargc++;
#endif
#endif
    /* Append mountpoint last (after all options) */
    fuseargv[fuseargc] = volume->mountpoint;
    fuseargc++;
    /* NULL-terminate the argument array for FUSE 3 compatibility */
    fuseargv[fuseargc] = NULL;
    arg->fuse_result =
        afp_register_fuse(fuseargc, (char **) fuseargv, volume);
    arg->fuse_errno = errno;
    arg->wait = 0;
    pthread_cond_signal(&volume->startup_condition_cond);
    /* Use NULL to send to stdout/syslog since this thread outlives the client connection */
    log_for_client(NULL, AFPFSD, LOG_NOTICE,
                   "Unmounting volume %s from %s\n",
                   volume->volume_name_printable,
                   volume->mountpoint);

    if (fsname) {
        free(fsname);
        fsname = NULL;
    }

    return NULL;
}

static int volopen(struct fuse_client * c, struct afp_volume * volume)
{
    char mesg[MAX_ERROR_LEN];
    unsigned int l = 0;
    memset(mesg, 0, MAX_ERROR_LEN);
    int rc = afp_connect_volume(volume, volume->server, mesg, &l, MAX_ERROR_LEN);
    log_for_client((void *) c, AFPFSD, LOG_ERR, mesg);
    return rc;
}


static unsigned char process_suspend(struct fuse_client * c)
{
    struct afp_server_suspend_request req;
    struct afp_server * s;
    memcpy(&req, c->incoming_string, sizeof(req));

    /* Find the server */
    if ((s = find_server_by_name(req.server_name)) == NULL) {
        log_for_client((void *) c, AFPFSD, LOG_ERR,
                       "%s is an unknown server\n", req.server_name);
        return AFP_SERVER_RESULT_ERROR;
    }

    if (afp_zzzzz(s)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    loop_disconnect(s);
    s->connect_state = SERVER_STATE_DISCONNECTED;
    log_for_client((void *) c, AFPFSD, LOG_NOTICE,
                   "Disconnected from %s\n", req.server_name);
    return AFP_SERVER_RESULT_OKAY;
}


static int afp_server_reconnect_loud(struct fuse_client * c,
                                     struct afp_server * s)
{
    char mesg[MAX_ERROR_LEN];
    unsigned int l = 2040;
    int rc;
    rc = afp_server_reconnect(s, mesg, &l, l);

    if (rc)
        log_for_client((void *) c, AFPFSD, LOG_ERR,
                       "%s", mesg);

    return rc;
}


static unsigned char process_resume(struct fuse_client * c)
{
    struct afp_server_resume_request req;
    struct afp_server * s;
    memcpy(&req, c->incoming_string, sizeof(req));

    /* Find the server */
    if ((s = find_server_by_name(req.server_name)) == NULL) {
        log_for_client((void *) c, AFPFSD, LOG_ERR,
                       "%s is an unknown server\n", req.server_name);
        return AFP_SERVER_RESULT_ERROR;
    }

    if (afp_server_reconnect_loud(c, s)) {
        log_for_client((void *) c, AFPFSD, LOG_ERR,
                       "Unable to reconnect to %s\n", req.server_name);
        return AFP_SERVER_RESULT_ERROR;
    }

    log_for_client((void *) c, AFPFSD, LOG_NOTICE,
                   "Resumed connection to %s\n", req.server_name);
    return AFP_SERVER_RESULT_OKAY;
}

static unsigned char process_unmount(struct fuse_client * c)
{
    struct afp_server_unmount_request req;
    struct afp_server * s;
    struct afp_volume * v;
    int j = 0;
    memcpy(&req, c->incoming_string, sizeof(req));

    for (s = get_server_base(); s; s = s->next) {
        for (j = 0; j < s->num_volumes; j++) {
            v = &s->volumes[j];

            if (strcmp(v->mountpoint, req.name) == 0) {
                goto found;
            }
        }
    }

    goto notfound;
found:

    if (v->mounted != AFP_VOLUME_MOUNTED) {
        log_for_client((void *) c, AFPFSD, LOG_NOTICE,
                       "%s was not mounted\n", v->mountpoint);
        return AFP_SERVER_RESULT_ERROR;
    }

    afp_unmount_volume(v);
    return AFP_SERVER_RESULT_OKAY;
notfound:
    log_for_client((void *)c, AFPFSD, LOG_WARNING,
                   "afpfs-ng doesn't have anything mounted on %s.\n", req.name);
    return AFP_SERVER_RESULT_ERROR;
}

static unsigned char process_ping(struct fuse_client * c)
{
    log_for_client((void *)c, AFPFSD, LOG_INFO,
                   "Ping!\n");
    return AFP_SERVER_RESULT_OKAY;
}

static unsigned char process_exit(struct fuse_client * c)
{
    log_for_client((void *)c, AFPFSD, LOG_INFO,
                   "Exiting\n");
    trigger_exit();
    /* Wake the main loop so exit is processed immediately. */
    signal_main_thread();
    return AFP_SERVER_RESULT_OKAY;
}

static unsigned char process_status(struct fuse_client * c)
{
    struct afp_server * s;
    char text[40960];
    int len = 40960;
    int buflen = 0;

    if (((unsigned long) c->incoming_size + 1) < sizeof(struct
            afp_server_status_request)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    if (afp_status_header(text, &len) < 0) {
        return AFP_SERVER_RESULT_ERROR;
    }

    buflen += snprintf(c->client_string + buflen, MAX_CLIENT_RESPONSE - buflen,
                       "%s", text);
    s = get_server_base();

    for (s = get_server_base(); s; s = s->next) {
        afp_status_server(s, text, &len);
        buflen += snprintf(c->client_string + buflen, MAX_CLIENT_RESPONSE - buflen,
                           "%s", text);
    }

    return AFP_SERVER_RESULT_OKAY;
}

static int process_mount(struct fuse_client * c)
{
    struct afp_server_mount_request req;
    struct afp_server * s = NULL;
    struct afp_volume * volume;
    struct afp_connection_request conn_req;
    int ret;
    struct stat lstat;

    if (((unsigned long) c->incoming_size) < sizeof(struct
            afp_server_mount_request)) {
        goto error;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    /* Check that the mount point exists and is a directory with proper permissions */
    struct stat mountpoint_stat;

    if (stat(req.mountpoint, &mountpoint_stat) != 0) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Mount point %s does not exist: %s\n",
                       req.mountpoint, strerror(errno));
        goto error;
    }

    if (!S_ISDIR(mountpoint_stat.st_mode)) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Mount point %s is not a directory\n",
                       req.mountpoint);
        goto error;
    }

    if ((ret = access(req.mountpoint, X_OK)) != 0) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Insufficient permissions on mount point %s: %s\n",
                       req.mountpoint, strerror(errno));
        goto error;
    }

    if (stat(FUSE_DEVICE, &lstat)) {
        printf("Could not find %s\n", FUSE_DEVICE);
        goto error;
    }

    if (access(FUSE_DEVICE, R_OK | W_OK) != 0) {
        log_for_client((void *)c, AFPFSD, LOG_NOTICE,
                       "Incorrect permissions on %s, mode of device"
                       " is %o, uid/gid is %d/%d.  But your effective "
                       "uid/gid is %d/%d\n",
                       FUSE_DEVICE, lstat.st_mode, lstat.st_uid,
                       lstat.st_gid,
                       geteuid(), getegid());
        goto error;
    }

    log_for_client(NULL, AFPFSD, LOG_INFO,
                   "Mounting %s from %s on %s\n",
                   (char *) req.url.volumename,
                   (char *) req.url.servername,
                   req.mountpoint);
    memset(&conn_req, 0, sizeof(conn_req));
    conn_req.url = req.url;
    conn_req.uam_mask = req.uam_mask;

    if ((s = afp_server_full_connect(c, &conn_req)) == NULL) {
        signal_main_thread();
        goto error;
    }

    if ((volume = mount_volume(c, s, req.url.volumename,
                               req.url.volpassword)) == NULL) {
        goto error;
    }

    volume->extra_flags |= req.volume_options;
    volume->mapping = req.map;
    afp_detect_mapping(volume);
    snprintf(volume->mountpoint, 255, "%s", req.mountpoint);
    /* Set the mount time to current time for the root directory's birth time */
    volume->mount_time = time(NULL);
    /* Create the new thread and block until we get an answer back */
    {
        pthread_mutex_t mutex;
        struct timespec ts;
        struct timeval tv;
        struct start_fuse_thread_arg arg;
        memset(&arg, 0, sizeof(arg));
        arg.client = c;
        arg.volume = volume;
        arg.wait = 1;
        arg.changeuid = req.changeuid;
        arg.fuse_options = req.fuse_options;
        gettimeofday(&tv, NULL);
        ts.tv_sec = tv.tv_sec;
        ts.tv_sec += 5;
        ts.tv_nsec = tv.tv_usec * 1000;
        pthread_mutex_init(&mutex, NULL);
        pthread_cond_init(&volume->startup_condition_cond, NULL);
        /* Kickoff a thread to see how quickly it exits.  If
         * it exits quickly, we have an error and it failed. */
        pthread_create(&volume->thread, NULL, start_fuse_thread, &arg);

        if (arg.wait) {
            /* Properly lock the mutex paired with the condition before waiting */
            pthread_mutex_lock(&mutex);
            ret = pthread_cond_timedwait(&volume->startup_condition_cond, &mutex, &ts);
            pthread_mutex_unlock(&mutex);

            if (ret != 0 && ret != ETIMEDOUT) {
                log_for_client((void *)c, AFPFSD, LOG_ERR,
                               "Error waiting for mount thread: %s\n", strerror(ret));
                volume->mounted = AFP_VOLUME_UNMOUNTED;
                goto error;
            }
        }

        report_fuse_errors(c);

        /* If timedout, the mount might still succeed, so don't check arg.fuse_result yet */
        if (ret == ETIMEDOUT) {
            log_for_client((void *)c, AFPFSD, LOG_NOTICE,
                           "Still trying to mount...\n");
            return 0;
        }

        switch (arg.fuse_result) {
        case 0:
            if (volume->mounted == AFP_VOLUME_UNMOUNTED) {
                /* Try and discover why */
                switch (arg.fuse_errno) {
                case ENOENT:
                    log_for_client((void *)c, AFPFSD, LOG_ERR,
                                   "Permission denied, maybe a problem with the fuse device or mountpoint?\n");
                    break;

                default:
                    log_for_client((void *)c, AFPFSD, LOG_ERR,
                                   "Mounting of volume %s from server %s failed.\n",
                                   volume->volume_name_printable,
                                   volume->server->server_name_printable);
                }

                goto error;
            } else {
                log_for_client((void *)c, AFPFSD, LOG_NOTICE,
                               "Mounting of volume %s from server %s succeeded.\n",
                               volume->volume_name_printable,
                               volume->server->server_name_printable);
                return 0;
            }

            break;

        default:
            volume->mounted = AFP_VOLUME_UNMOUNTED;
            log_for_client((void *)c, AFPFSD, LOG_NOTICE,
                           "Unknown error %d, %d.\n",
                           arg.fuse_result, arg.fuse_errno);
            goto error;
        }
    }
    return AFP_SERVER_RESULT_OKAY;
error:

    if ((s) && (!something_is_mounted(s))) {
        afp_server_remove(s);
    }

    signal_main_thread();
    return AFP_SERVER_RESULT_ERROR;
}


/*
 * Stateless API command handlers
 *
 * These handlers implement the stateless file I/O and metadata operations.
 * Each operation is self-contained and uses the file handle table for
 * serialization.
 */

/* Attach to a volume - connect to server, open volume, return volumeid */
static unsigned char process_sl_attach(struct fuse_client *c)
{
    struct afp_server_attach_request req;
    struct afp_server_attach_response resp;
    struct afp_server *s = NULL;
    struct afp_volume *volume;
    struct afp_connection_request conn_req;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));

    fprintf(stderr, "process_sl_attach: server=%s volume=%s user=%s\n",
            req.url.servername, req.url.volumename, req.url.username);

    log_for_client((void *)c, AFPFSD, LOG_INFO,
                   "Stateless attach to %s on %s\n",
                   req.url.volumename, req.url.servername);

    /* Connect to server */
    memset(&conn_req, 0, sizeof(conn_req));
    conn_req.url = req.url;
    conn_req.uam_mask = 0xFFFF;  /* Allow all UAMs */

    fprintf(stderr, "process_sl_attach: calling afp_server_full_connect\n");
    s = afp_server_full_connect(c, &conn_req);
    fprintf(stderr, "process_sl_attach: afp_server_full_connect returned %p\n", (void *)s);
    if (!s) {
        fprintf(stderr, "process_sl_attach: connection failed!\n");
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Failed to connect to server %s\n", req.url.servername);
        memset(&resp, 0, sizeof(resp));
        resp.header.result = AFP_SERVER_RESULT_NOTCONNECTED;
        resp.header.len = sizeof(resp);
        write(c->fd, &resp, sizeof(resp));
        return AFP_SERVER_RESULT_NOTCONNECTED;
    }

    /* Mount the volume (without FUSE - just open it) */
    volume = mount_volume(c, s, req.url.volumename, req.url.volpassword);
    if (!volume) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Failed to mount volume %s\n", req.url.volumename);
        memset(&resp, 0, sizeof(resp));
        resp.header.result = AFP_SERVER_RESULT_NOVOLUME;
        resp.header.len = sizeof(resp);
        write(c->fd, &resp, sizeof(resp));
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    volume->extra_flags |= req.volume_options;
    afp_detect_mapping(volume);

    /* Mark volume as attached (but not FUSE-mounted) */
    volume->mounted = AFP_VOLUME_MOUNTED;

    /* Send response with volumeid (the volume pointer) */
    memset(&resp, 0, sizeof(resp));
    resp.header.result = AFP_SERVER_RESULT_OKAY;
    resp.header.len = sizeof(resp);
    resp.volumeid = (volumeid_t)volume;

    log_for_client((void *)c, AFPFSD, LOG_INFO,
                   "Attached volume %s, volumeid=%p\n",
                   req.url.volumename, (void *)volume);

    write(c->fd, &resp, sizeof(resp));
    return AFP_SERVER_RESULT_OKAY;
}

/* Detach from a volume - close volume and disconnect */
static unsigned char process_sl_detach(struct fuse_client *c)
{
    struct afp_server_detach_request req;
    struct afp_server_detach_response resp;
    struct afp_volume *volume;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);

    if (!volume) {
        memset(&resp, 0, sizeof(resp));
        resp.header.result = AFP_SERVER_RESULT_NOVOLUME;
        resp.header.len = sizeof(resp);
        write(c->fd, &resp, sizeof(resp));
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    log_for_client((void *)c, AFPFSD, LOG_INFO,
                   "Detaching volume %s\n", volume->volume_name_printable);

    /* Unmount the volume */
    afp_unmount_volume(volume);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = AFP_SERVER_RESULT_OKAY;
    resp.header.len = sizeof(resp);
    snprintf(resp.detach_message, sizeof(resp.detach_message),
             "Volume detached successfully");

    write(c->fd, &resp, sizeof(resp));
    return AFP_SERVER_RESULT_OKAY;
}

/* Open file and return fileid */
static unsigned char process_sl_open(struct fuse_client *c)
{
    struct afp_server_open_request req;
    struct afp_server_open_response resp;
    struct afp_volume *volume;
    struct afp_file_info *fp = NULL;
    struct daemon_file_handle *handle;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        log_for_client((void *)c, AFPFSD, LOG_ERR, "Invalid volume ID\n");
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_open(volume, req.path, req.mode, &fp);
    if (ret != 0 || !fp) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Failed to open %s: %d\n", req.path, ret);
        return AFP_SERVER_RESULT_ERROR;
    }

    handle = allocate_file_handle(volume, fp);
    if (!handle) {
        ml_close(volume, req.path, fp);
        return AFP_SERVER_RESULT_ERROR;
    }

    /* Send response with fileid */
    memset(&resp, 0, sizeof(resp));
    resp.header.result = AFP_SERVER_RESULT_OKAY;
    resp.header.len = sizeof(resp);
    resp.fileid = handle->fileid;

    if (write(c->fd, &resp, sizeof(resp)) < 0) {
        release_file_handle(handle);
        return AFP_SERVER_RESULT_ERROR;
    }

    return AFP_SERVER_RESULT_OKAY;
}

/* Read from file using fileid */
static unsigned char process_sl_read(struct fuse_client *c)
{
    struct afp_server_read_request req;
    struct afp_server_read_response resp;
    struct daemon_file_handle *handle;
    char *buffer = NULL;
    int eof = 0;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    handle = lookup_file_handle(req.fileid);
    if (!handle) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Invalid file ID: %u\n", req.fileid);
        return AFP_SERVER_RESULT_ENOENT;
    }

    buffer = malloc(req.length);
    if (!buffer) {
        release_file_handle(handle);
        return AFP_SERVER_RESULT_ERROR;
    }

    lock_file_handle(handle);
    ret = ml_read(handle->volume, handle->fp->name, buffer, req.length,
                  req.start, handle->fp, &eof);
    unlock_file_handle(handle);

    if (ret < 0) {
        free(buffer);
        release_file_handle(handle);
        return AFP_SERVER_RESULT_ERROR;
    }

    /* Send response header */
    memset(&resp, 0, sizeof(resp));
    resp.header.result = AFP_SERVER_RESULT_OKAY;
    resp.header.len = sizeof(resp) + ret;
    resp.received = ret;
    resp.eof = eof;

    /* Write header then data */
    if (write(c->fd, &resp, sizeof(resp)) < 0 ||
        (ret > 0 && write(c->fd, buffer, ret) < 0)) {
        free(buffer);
        release_file_handle(handle);
        return AFP_SERVER_RESULT_ERROR;
    }

    free(buffer);
    release_file_handle(handle);
    return AFP_SERVER_RESULT_OKAY;
}

/* Write to file using fileid */
static unsigned char process_sl_write(struct fuse_client *c)
{
    struct afp_server_write_request req;
    struct afp_server_write_response resp;
    struct daemon_file_handle *handle;
    const char *data;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    handle = lookup_file_handle(req.fileid);
    if (!handle) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Invalid file ID: %u\n", req.fileid);
        return AFP_SERVER_RESULT_ENOENT;
    }

    /* Data follows the request struct (for inline mode) */
    data = c->incoming_string + sizeof(req);

    lock_file_handle(handle);
    ret = ml_write(handle->volume, handle->fp->name, data, req.length,
                   req.offset, handle->fp, geteuid(), getegid());
    unlock_file_handle(handle);

    /* Send response */
    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret >= 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);
    resp.written = (ret >= 0) ? ret : 0;

    if (write(c->fd, &resp, sizeof(resp)) < 0) {
        release_file_handle(handle);
        return AFP_SERVER_RESULT_ERROR;
    }

    release_file_handle(handle);
    return (ret >= 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
}

/* Flush file using fileid */
static unsigned char process_sl_flush(struct fuse_client *c)
{
    struct afp_server_flush_request req;
    struct afp_server_flush_response resp;
    struct daemon_file_handle *handle;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    handle = lookup_file_handle(req.fileid);
    if (!handle) {
        return AFP_SERVER_RESULT_ENOENT;
    }

    lock_file_handle(handle);
    ret = afp_flushfork(handle->volume, handle->fp->forkid);
    unlock_file_handle(handle);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    release_file_handle(handle);
    return resp.header.result;
}

/* Close file using fileid */
static unsigned char process_sl_close(struct fuse_client *c)
{
    struct afp_server_close_request req;
    struct afp_server_close_response resp;
    struct daemon_file_handle *handle;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    handle = lookup_file_handle(req.fileid);
    if (!handle) {
        return AFP_SERVER_RESULT_ENOENT;
    }

    lock_file_handle(handle);
    ml_close(handle->volume, handle->fp->name, handle->fp);
    unlock_file_handle(handle);

    /* Release twice: once for lookup, once to actually free */
    release_file_handle(handle);
    release_file_handle(handle);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = AFP_SERVER_RESULT_OKAY;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return AFP_SERVER_RESULT_OKAY;
}

/* Stat file by path */
static unsigned char process_sl_stat(struct fuse_client *c)
{
    struct afp_server_stat_request req;
    struct afp_server_stat_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    memset(&resp, 0, sizeof(resp));
    ret = ml_getattr(volume, req.path, &resp.stat);

    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ENOENT;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Create and open file */
static unsigned char process_sl_create(struct fuse_client *c)
{
    struct afp_server_create_request req;
    struct afp_server_create_response resp;
    struct afp_volume *volume;
    struct afp_file_info *fp = NULL;
    struct daemon_file_handle *handle;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    /* Create the file */
    ret = ml_creat(volume, req.path, req.permissions);
    if (ret != 0) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Failed to create %s: %d\n", req.path, ret);
        return AFP_SERVER_RESULT_ERROR;
    }

    /* Open it */
    ret = ml_open(volume, req.path, req.mode | O_CREAT, &fp);
    if (ret != 0 || !fp) {
        return AFP_SERVER_RESULT_ERROR;
    }

    handle = allocate_file_handle(volume, fp);
    if (!handle) {
        ml_close(volume, req.path, fp);
        return AFP_SERVER_RESULT_ERROR;
    }

    memset(&resp, 0, sizeof(resp));
    resp.header.result = AFP_SERVER_RESULT_OKAY;
    resp.header.len = sizeof(resp);
    resp.fileid = handle->fileid;

    write(c->fd, &resp, sizeof(resp));
    return AFP_SERVER_RESULT_OKAY;
}

/* Truncate file by path */
static unsigned char process_sl_truncate(struct fuse_client *c)
{
    struct afp_server_truncate_request req;
    struct afp_server_truncate_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_truncate(volume, req.path, req.size);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Read directory */
static unsigned char process_sl_readdir(struct fuse_client *c)
{
    struct afp_server_readdir_request req;
    struct afp_server_readdir_response resp;
    struct afp_volume *volume;
    struct afp_file_info *filebase = NULL, *fp;
    int ret, count = 0;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_readdir(volume, req.path, &filebase);
    if (ret != 0) {
        memset(&resp, 0, sizeof(resp));
        resp.header.result = AFP_SERVER_RESULT_ERROR;
        resp.header.len = sizeof(resp);
        write(c->fd, &resp, sizeof(resp));
        return AFP_SERVER_RESULT_ERROR;
    }

    /* Count files */
    for (fp = filebase; fp; fp = fp->next) {
        count++;
    }

    /* Send response header */
    memset(&resp, 0, sizeof(resp));
    resp.header.result = AFP_SERVER_RESULT_OKAY;
    resp.numfiles = count;
    resp.eod = 1;

    /* Calculate total size for the response */
    resp.header.len = sizeof(resp) + count * sizeof(struct afp_file_info_basic);

    write(c->fd, &resp, sizeof(resp));

    /* Send file info entries */
    for (fp = filebase; fp; fp = fp->next) {
        struct afp_file_info_basic basic;
        memset(&basic, 0, sizeof(basic));
        snprintf(basic.name, AFP_MAX_PATH, "%s", fp->name);
        basic.isdir = fp->isdir;
        basic.size = fp->size;
        basic.modification_date = fp->modification_date;
        basic.creation_date = fp->creation_date;
        write(c->fd, &basic, sizeof(basic));
    }

    afp_ml_filebase_free(&filebase);
    return AFP_SERVER_RESULT_OKAY;
}

/* Mkdir */
static unsigned char process_sl_mkdir(struct fuse_client *c)
{
    struct afp_server_mkdir_request req;
    struct afp_server_mkdir_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_mkdir(volume, req.path, req.mode);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Rmdir */
static unsigned char process_sl_rmdir(struct fuse_client *c)
{
    struct afp_server_rmdir_request req;
    struct afp_server_rmdir_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_rmdir(volume, req.path);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Unlink */
static unsigned char process_sl_unlink(struct fuse_client *c)
{
    struct afp_server_unlink_request req;
    struct afp_server_unlink_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_unlink(volume, req.path);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Rename */
static unsigned char process_sl_rename(struct fuse_client *c)
{
    struct afp_server_rename_request req;
    struct afp_server_rename_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_rename(volume, req.from_path, req.to_path);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Symlink */
static unsigned char process_sl_symlink(struct fuse_client *c)
{
    struct afp_server_symlink_request req;
    struct afp_server_symlink_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_symlink(volume, req.target, req.linkpath);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Readlink */
static unsigned char process_sl_readlink(struct fuse_client *c)
{
    struct afp_server_readlink_request req;
    struct afp_server_readlink_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    memset(&resp, 0, sizeof(resp));
    ret = ml_readlink(volume, req.path, resp.target, sizeof(resp.target));

    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Chmod */
static unsigned char process_sl_chmod(struct fuse_client *c)
{
    struct afp_server_chmod_request req;
    struct afp_server_chmod_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_chmod(volume, req.path, req.mode);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Chown */
static unsigned char process_sl_chown(struct fuse_client *c)
{
    struct afp_server_chown_request req;
    struct afp_server_chown_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_chown(volume, req.path, req.uid, req.gid);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Utime */
static unsigned char process_sl_utime(struct fuse_client *c)
{
    struct afp_server_utime_request req;
    struct afp_server_utime_response resp;
    struct afp_volume *volume;
    struct utimbuf timebuf;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    timebuf.actime = req.atime_sec;
    timebuf.modtime = req.mtime_sec;
    ret = ml_utime(volume, req.path, &timebuf);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Statfs */
static unsigned char process_sl_statfs(struct fuse_client *c)
{
    struct afp_server_statfs_request req;
    struct afp_server_statfs_response resp;
    struct afp_volume *volume;
    struct statvfs svfs;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_statfs(volume, req.path, &svfs);

    memset(&resp, 0, sizeof(resp));
    if (ret == 0) {
        resp.header.result = AFP_SERVER_RESULT_OKAY;
        resp.blocks = svfs.f_blocks;
        resp.bfree = svfs.f_bfree;
        resp.bavail = svfs.f_bavail;
        resp.files = svfs.f_files;
        resp.ffree = svfs.f_ffree;
        resp.bsize = svfs.f_bsize;
        resp.namelen = svfs.f_namemax;
    } else {
        resp.header.result = AFP_SERVER_RESULT_ERROR;
    }
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Getxattr */
static unsigned char process_sl_getxattr(struct fuse_client *c)
{
    struct afp_server_getxattr_request req;
    struct afp_server_getxattr_response resp;
    struct afp_volume *volume;
    char *buffer = NULL;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    if (req.size > 0) {
        buffer = malloc(req.size);
        if (!buffer) {
            return AFP_SERVER_RESULT_ERROR;
        }
    }

    ret = ml_getxattr(volume, req.path, req.name, buffer, req.size);

    memset(&resp, 0, sizeof(resp));
    if (ret >= 0) {
        resp.header.result = AFP_SERVER_RESULT_OKAY;
        resp.size = ret;
        resp.header.len = sizeof(resp) + (buffer ? ret : 0);
    } else {
        resp.header.result = AFP_SERVER_RESULT_ERROR;
        resp.header.len = sizeof(resp);
    }

    write(c->fd, &resp, sizeof(resp));
    if (ret > 0 && buffer) {
        write(c->fd, buffer, ret);
    }

    if (buffer) {
        free(buffer);
    }
    return resp.header.result;
}

/* Setxattr */
static unsigned char process_sl_setxattr(struct fuse_client *c)
{
    struct afp_server_setxattr_request req;
    struct afp_server_setxattr_response resp;
    struct afp_volume *volume;
    const char *value;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    /* Value data follows the request struct */
    value = c->incoming_string + sizeof(req);

    ret = ml_setxattr(volume, req.path, req.name, value, req.size, req.flags);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}

/* Listxattr */
static unsigned char process_sl_listxattr(struct fuse_client *c)
{
    struct afp_server_listxattr_request req;
    struct afp_server_listxattr_response resp;
    struct afp_volume *volume;
    char *buffer = NULL;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    if (req.size > 0) {
        buffer = malloc(req.size);
        if (!buffer) {
            return AFP_SERVER_RESULT_ERROR;
        }
    }

    ret = ml_listxattr(volume, req.path, buffer, req.size);

    memset(&resp, 0, sizeof(resp));
    if (ret >= 0) {
        resp.header.result = AFP_SERVER_RESULT_OKAY;
        resp.size = ret;
        resp.header.len = sizeof(resp) + (buffer ? ret : 0);
    } else {
        resp.header.result = AFP_SERVER_RESULT_ERROR;
        resp.header.len = sizeof(resp);
    }

    write(c->fd, &resp, sizeof(resp));
    if (ret > 0 && buffer) {
        write(c->fd, buffer, ret);
    }

    if (buffer) {
        free(buffer);
    }
    return resp.header.result;
}

/* Removexattr */
static unsigned char process_sl_removexattr(struct fuse_client *c)
{
    struct afp_server_removexattr_request req;
    struct afp_server_removexattr_response resp;
    struct afp_volume *volume;
    int ret;

    if ((unsigned long)c->incoming_size < sizeof(req)) {
        return AFP_SERVER_RESULT_ERROR;
    }

    memcpy(&req, c->incoming_string, sizeof(req));
    volume = find_volume_by_id(req.volumeid);
    if (!volume) {
        return AFP_SERVER_RESULT_NOVOLUME;
    }

    ret = ml_removexattr(volume, req.path, req.name);

    memset(&resp, 0, sizeof(resp));
    resp.header.result = (ret == 0) ? AFP_SERVER_RESULT_OKAY : AFP_SERVER_RESULT_ERROR;
    resp.header.len = sizeof(resp);

    write(c->fd, &resp, sizeof(resp));
    return resp.header.result;
}


static void *process_command_thread(void * other)
{
    struct fuse_client * c = other;
    int ret = 0;
    char tosend[sizeof(struct afp_server_response) + MAX_CLIENT_RESPONSE];
    struct afp_server_response response;
    const struct afp_server_request_header *hdr;

    memset(c->client_string, 0, sizeof(c->client_string));

    /* Parse the request header */
    hdr = (const struct afp_server_request_header *)c->incoming_string;

    switch (hdr->command) {
    case AFP_SERVER_COMMAND_MOUNT:
        ret = process_mount(c);
        break;

    case AFP_SERVER_COMMAND_STATUS:
        ret = process_status(c);
        break;

    case AFP_SERVER_COMMAND_UNMOUNT:
        ret = process_unmount(c);
        break;

    case AFP_SERVER_COMMAND_SUSPEND:
        ret = process_suspend(c);
        break;

    case AFP_SERVER_COMMAND_RESUME:
        ret = process_resume(c);
        break;

    case AFP_SERVER_COMMAND_PING:
        ret = process_ping(c);
        break;

    case AFP_SERVER_COMMAND_EXIT:
        ret = process_exit(c);
        break;

    /* Stateless API commands - these send their own responses */
    case AFP_SERVER_COMMAND_ATTACH:
        (void)process_sl_attach(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_DETACH:
        (void)process_sl_detach(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_OPEN:
        (void)process_sl_open(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_READ:
        (void)process_sl_read(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_WRITE:
        (void)process_sl_write(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_FLUSH:
        (void)process_sl_flush(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_CLOSE:
        (void)process_sl_close(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_STAT:
        (void)process_sl_stat(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_CREATE:
        (void)process_sl_create(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_TRUNCATE:
        (void)process_sl_truncate(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_READDIR:
        (void)process_sl_readdir(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_MKDIR:
        (void)process_sl_mkdir(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_RMDIR:
        (void)process_sl_rmdir(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_UNLINK:
        (void)process_sl_unlink(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_RENAME:
        (void)process_sl_rename(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_SYMLINK:
        (void)process_sl_symlink(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_READLINK:
        (void)process_sl_readlink(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_CHMOD:
        (void)process_sl_chmod(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_CHOWN:
        (void)process_sl_chown(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_UTIME:
        (void)process_sl_utime(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_STATFS:
        (void)process_sl_statfs(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_GETXATTR:
        (void)process_sl_getxattr(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_SETXATTR:
        (void)process_sl_setxattr(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_LISTXATTR:
        (void)process_sl_listxattr(c);
        goto stateless_cleanup;

    case AFP_SERVER_COMMAND_REMOVEXATTR:
        (void)process_sl_removexattr(c);
        goto stateless_cleanup;

    default:
        log_for_client((void *)c, AFPFSD, LOG_ERR, "Unknown command: %d\n", hdr->command);
    }

    /* Send response */
    response.result = ret;
    response.len = strlen(c->client_string);
    bcopy(&response, tosend, sizeof(response));
    bcopy(c->client_string, tosend + sizeof(response), response.len);
    ret = write(c->fd, tosend, sizeof(response) + response.len);

    if (ret < 0) {
        perror("Writing");
    }

    if ((!c) || (c->fd == 0)) {
        return NULL;
    }

    /* fd was already removed from select set in process_command() */
    close(c->fd);
    remove_client(c);
    return NULL;

stateless_cleanup:
    /* Stateless commands send their own responses, just clean up.
     * fd was already removed from select set in process_command() */
    if (c && c->fd > 0) {
        close(c->fd);
        remove_client(c);
    }
    return NULL;
}

static int process_command(struct fuse_client * c)
{
    int ret;
    int fd;

    ret = read(c->fd, &c->incoming_string, AFP_CLIENT_INCOMING_BUF);

    if (ret <= 0) {
        perror("reading");
        goto out;
    }

    c->incoming_size = ret;

    /* Remove fd from select set immediately to prevent the main loop
     * from trying to read from it again while the thread is processing.
     * The thread will close the fd and remove the client when done.
     * Note: rm_fd_and_signal also wakes the main thread, which is fine. */
    rm_fd_and_signal(c->fd);

    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, process_command_thread, c);
    pthread_attr_destroy(&attr);
    return 0;
out:
    fd = c->fd;
    c->fd = 0;
    remove_client(c);
    close(fd);
    rm_fd_and_signal(fd);
    return 0;
}


static struct afp_volume *mount_volume(struct fuse_client * c,
                                       struct afp_server * server, char *volname, char *volpassword)
{
    struct afp_volume * using_volume;
    using_volume = find_volume_by_name(server, volname);

    if (!using_volume) {
        log_for_client((void *) c, AFPFSD, LOG_ERR,
                       "Volume %s does not exist on server %s.\n", volname,
                       server->server_name_printable);

        if (server->num_volumes) {
            char names[VOLNAME_LEN];
            afp_list_volnames(server, names, VOLNAME_LEN);
            log_for_client((void *)c, AFPFSD, LOG_ERR,
                           "Choose from: %s\n", names);
        }

        goto error;
    }

    if (using_volume->mounted == AFP_VOLUME_MOUNTED) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "Volume %s is already mounted on %s\n", volname,
                       using_volume->mountpoint);
        goto error;
    }

    if (using_volume->flags & HasPassword) {
        bcopy(volpassword, using_volume->volpassword, AFP_VOLPASS_LEN);

        if (strlen(volpassword) < 1) {
            log_for_client((void *) c, AFPFSD, LOG_ERR, "Volume password needed\n");
            goto error;
        }
    }  else {
        memset(using_volume->volpassword, 0, AFP_VOLPASS_LEN);
    }

    if (volopen(c, using_volume)) {
        log_for_client((void *) c, AFPFSD, LOG_ERR, "Could not mount volume %s\n",
                       volname);
        goto error;
    }

    using_volume->server = server;
    return using_volume;
error:
    return NULL;
}


static struct libafpclient client = {
    .unmount_volume = fuse_unmount_volume,
    .log_for_client = fuse_log_for_client,
    .forced_ending_hook = fuse_forced_ending_hook,
    .scan_extra_fds = fuse_scan_extra_fds
};

int fuse_register_afpclient(void)
{
    libafpclient_register(&client);
    return 0;
}



