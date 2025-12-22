/*
 *  daemon.c
 *
 *  Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>
 *
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <fuse.h>
#include <glob.h>

#include "afp.h"
#include "dsi.h"
#include "afpfsd.h"
#include "utils.h"
#include "daemon.h"
#include "commands.h"


static int debug_mode = 0;
static char commandfilename[PATH_MAX];
static int current_log_method = LOG_METHOD_SYSLOG;
static int current_log_level = LOG_NOTICE;

/* SIGCHLD handler to immediately reap child processes */
static void sigchld_handler(int sig)
{
    (void)sig;  /* Unused parameter */
    int status;

    /* Reap all available child processes without blocking.
     * We don't track PIDs here because modifying child_list from a signal
     * handler would require async-signal-safe operations. The main loop's
     * timeout will clean up the tracking list safely. */
    while (waitpid(-1, &status, WNOHANG) > 0) {
        /* Child has been reaped */
    }
}

int get_debug_mode(void)
{
    return debug_mode;
}

void fuse_forced_ending_hook(void)
{
    struct afp_volume * volume;

    for (struct afp_server * s = get_server_base(); s;) {
        /* Save next pointer before unmounting */
        struct afp_server * next_server = s->next;

        if (s->connect_state == SERVER_STATE_CONNECTED) {
            for (int i = 0; i < s->num_volumes; i++) {
                volume = &s->volumes[i];

                if (volume->mounted == AFP_VOLUME_MOUNTED)
                    log_for_client(NULL, AFPFSD, LOG_NOTICE,
                                   "Unmounting %s\n", volume->mountpoint);

                afp_unmount_volume(volume);
            }
        }

        s = next_server;
    }
}

int fuse_unmount_volume(struct afp_volume * volume)
{
    if (volume->priv) {
        pthread_t self = pthread_self();
        pthread_t vol_thread = volume->thread;
        int is_same_thread = pthread_equal(self, vol_thread);

        if (is_same_thread) {
            /* Called from within the FUSE thread (e.g., from afp_destroy callback).
             * Don't call fuse_exit() or pthread_kill() - just return and let the
             * FUSE library handle thread shutdown naturally. */
        } else {
            /* Called from external thread (e.g., client handler).
             * Safely shut down the FUSE thread. */
            fuse_exit((struct fuse *)volume->priv);
            pthread_kill(volume->thread, SIGHUP);
            pthread_join(volume->thread, NULL);
        }
    }

    return 0;
}


static int startup_listener(void)
{
    int command_fd;
    struct sockaddr_un sa;
    int len;

    if ((command_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        goto error;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;

    if (strlcpy(sa.sun_path, commandfilename,
                sizeof(sa.sun_path)) >= sizeof(sa.sun_path)) {
        fprintf(stderr, "Socket path too long: %s\n", commandfilename);
        goto error;
    }

#ifdef __APPLE__
    /* macOS BSD-style sockaddr - use full structure size */
    sa.sun_len = sizeof(sa);
    len = sizeof(sa);
#else
    len = sizeof(sa.sun_family) + strlen(sa.sun_path) + 1;
#endif

    if (bind(command_fd, (struct sockaddr *)&sa, len) < 0)  {
        perror("binding");
        close(command_fd);
        goto error;
    }

    listen(command_fd, 5); /* Just one at a time */
    return command_fd;
error:
    return -1;
}

void close_commands(int command_fd)
{
    close(command_fd);
    unlink(commandfilename);
}

static void usage(void)
{
    printf("afpfs-ng %s - Apple Filing Protocol client FUSE daemon\n"
           "Usage: afpfsd [OPTION]\n"
           "  -l, --logmethod    Either 'syslog' or 'stdout'\n"
           "  -v, --loglevel     LOG_DEBUG|LOG_INFO|LOG_NOTICE|LOG_WARNING|LOG_ERR\n"
           "  -f, --foreground   Do not fork\n"
           "  -d, --debug        Do not fork, debug loglevel, log to stdout\n"
           "  -m, --manager      Run as a manager daemon\n"
           "  -s, --socket-id    Socket filename (for per-mount daemon support)\n",
           AFPFS_VERSION);
}

static int parse_level(const char *arg, int *loglevel_out)
{
    if (!arg || !loglevel_out) {
        return -1;
    }

    if (strcasecmp(arg, "debug") == 0 || strcasecmp(arg, "LOG_DEBUG") == 0) {
        *loglevel_out = LOG_DEBUG;
    } else if (strcasecmp(arg, "info") == 0 || strcasecmp(arg, "LOG_INFO") == 0) {
        *loglevel_out = LOG_INFO;
    } else if (strcasecmp(arg, "notice") == 0
               || strcasecmp(arg, "LOG_NOTICE") == 0) {
        *loglevel_out = LOG_NOTICE;
    } else if (strcasecmp(arg, "warning") == 0 || strcasecmp(arg, "warn") == 0 ||
               strcasecmp(arg, "LOG_WARNING") == 0) {
        *loglevel_out = LOG_WARNING;
    } else if (strcasecmp(arg, "err") == 0 || strcasecmp(arg, "error") == 0 ||
               strcasecmp(arg, "LOG_ERR") == 0) {
        *loglevel_out = LOG_ERR;
    } else {
        return -1;
    }

    return 0;
}

static int remove_other_daemon(void)
{
    int sock;
    struct sockaddr_un servaddr;
    int len = 0, ret;
    char incoming_buffer[MAX_CLIENT_RESPONSE];
    struct timeval tv;
    fd_set rds;
    struct afp_server_request_header ping_req = {0};

    if (access(commandfilename, F_OK) != 0) {
        goto doesnotexist;    /* file doesn't even exist */
    }

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("Opening socket");
        goto error;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;

    if (strlcpy(servaddr.sun_path, commandfilename,
                sizeof(servaddr.sun_path)) >= sizeof(servaddr.sun_path)) {
        goto error; /* Path too long */
    }

    if ((connect(sock, (struct sockaddr *) &servaddr,
                 sizeof(servaddr.sun_family) +
                 sizeof(servaddr.sun_path))) < 0) {
        goto dead;
    }

    /* Try writing a PING request with header */
    ping_req.command = AFP_SERVER_COMMAND_PING;
    ping_req.len = sizeof(ping_req);
    ping_req.close = 0;

    if (write(sock, &ping_req, sizeof(ping_req)) < (ssize_t)sizeof(ping_req)) {
        goto dead;
    }

    /* See if we get a response */
    memset(incoming_buffer, 0, MAX_CLIENT_RESPONSE);
    FD_ZERO(&rds);
    FD_SET(sock, &rds);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    ret = select(sock + 1, &rds, NULL, NULL, &tv);

    if (ret == 0) {
        goto dead; /* Timeout */
    }

    if (ret < 0) {
        goto error; /* some sort of select error */
    }

    /* Let's see if we got a sane message back */
    len = read(sock, incoming_buffer, MAX_CLIENT_RESPONSE);

    if (len < 1) {
        goto dead;
    }

    /* Okay, the server is live */
    close(sock);
    return -1;
dead:
    close(sock);

    /* See if we can remove it */
    if (access(commandfilename, F_OK) == 0) {
        if (unlink(commandfilename) != 0) {
            log_for_client(NULL, AFPFSD, LOG_NOTICE,
                           "Cannot remove command file");
            return -1;
        }
    }

    return 0;
doesnotexist:
    return 0;
error:
    close(sock);
    return -1;
}

/* Manager daemon child tracking */
struct manager_child {
    pid_t pid;
    char socket_id[PATH_MAX];
    char mountpoint[PATH_MAX];
    struct manager_child *next;
};

static struct manager_child *child_list = NULL;

/* Ask any afpfsd listening on the provided socket path to exit gracefully. */
static void send_exit_to_socket_path(const char *socket_path)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock < 0) {
        return;
    }

    struct sockaddr_un sa;

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    size_t len = strnlen(socket_path, sizeof(sa.sun_path));

    if (len >= sizeof(sa.sun_path)) {
        goto out;
    }

    memcpy(sa.sun_path, socket_path, len + 1);

    if (connect(sock, (struct sockaddr *)&sa,
                sizeof(sa.sun_family) + len + 1) == 0) {
        unsigned char cmd = AFP_SERVER_COMMAND_EXIT;
        (void)write(sock, &cmd, 1);
    }

out:
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

/* Ask a mount daemon to exit gracefully over its control socket. */
static void send_exit_to_child(const struct manager_child *child)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock < 0) {
        return;
    }

    struct sockaddr_un sa;

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    size_t len = strnlen(child->socket_id, sizeof(child->socket_id));

    if (len >= sizeof(sa.sun_path)) {
        return; /* Socket path too long */
    }

    memcpy(sa.sun_path, child->socket_id, len + 1);

    if (connect(sock, (struct sockaddr *)&sa,
                sizeof(sa.sun_family) + len + 1) == 0) {
        unsigned char cmd = AFP_SERVER_COMMAND_EXIT;
        (void)write(sock, &cmd, 1);
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
}

static void add_child(pid_t pid, const char *socket_id, const char *mountpoint)
{
    struct manager_child *child = malloc(sizeof(struct manager_child));

    if (!child) {
        return;
    }

    child->pid = pid;
    snprintf(child->socket_id, sizeof(child->socket_id), "%s", socket_id);
    snprintf(child->mountpoint, sizeof(child->mountpoint), "%s", mountpoint);
    child->next = child_list;
    child_list = child;
}

static void remove_child(pid_t pid)
{
    struct manager_child **curr = &child_list;

    while (*curr) {
        if ((*curr)->pid == pid) {
            struct manager_child *to_free = *curr;
            *curr = (*curr)->next;
            free(to_free);
            return;
        }

        curr = &(*curr)->next;
    }
}

static void cleanup_all_children(void)
{
    struct manager_child *child = child_list;
    /* Also notify any stray per-mount daemons that were not tracked. */
    {
        glob_t g = {0};
        char pattern[PATH_MAX];
        int len = snprintf(pattern, sizeof(pattern), "%s-%u*", SERVER_FILENAME,
                           geteuid());

        if (len > 0 && (size_t)len < sizeof(pattern)) {
            if (glob(pattern, 0, NULL, &g) == 0) {
                for (size_t i = 0; i < g.gl_pathc; i++) {
                    const char *path = g.gl_pathv[i];

                    /* Skip our own manager socket to avoid recursion. */
                    if (strcmp(path, commandfilename) == 0) {
                        continue;
                    }

                    send_exit_to_socket_path(path);
                }
            }

            globfree(&g);
        }
    }

    while (child) {
        send_exit_to_child(child);
        child = child->next;
    }

    /* Short grace period. */
    sleep(1);
    /* Force-stop any stubborn children. */
    child = child_list;

    while (child) {
        kill(child->pid, SIGTERM);
        child = child->next;
    }

    sleep(1);
    child = child_list;

    while (child) {
        int status;
        kill(child->pid, SIGKILL);
        waitpid(child->pid, &status, WNOHANG);
        child = child->next;
    }

    while (child_list) {
        remove_child(child_list->pid);
    }
}

static int start_mount_daemon(char *socket_id, const char *mountpoint)
{
    pid_t pid = fork();

    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        /* Child process - exec mount daemon */
        char log_method_str[16];
        char log_level_str[16];

        /* Convert log method to string */
        if (current_log_method & LOG_METHOD_STDOUT) {
            snprintf(log_method_str, sizeof(log_method_str), "stdout");
        } else {
            snprintf(log_method_str, sizeof(log_method_str), "syslog");
        }

        /* Convert log level to string */
        switch (current_log_level) {
        case LOG_DEBUG:
            snprintf(log_level_str, sizeof(log_level_str), "debug");
            break;

        case LOG_INFO:
            snprintf(log_level_str, sizeof(log_level_str), "info");
            break;

        case LOG_NOTICE:
            snprintf(log_level_str, sizeof(log_level_str), "notice");
            break;

        case LOG_WARNING:
            snprintf(log_level_str, sizeof(log_level_str), "warning");
            break;

        case LOG_ERR:
            snprintf(log_level_str, sizeof(log_level_str), "err");
            break;

        default:
            snprintf(log_level_str, sizeof(log_level_str), "notice");
        }

        char *argv[8];
        argv[0] = "afpfsd";
        argv[1] = "--socket-id";
        argv[2] = socket_id;
        argv[3] = "--logmethod";
        argv[4] = log_method_str;
        argv[5] = "--loglevel";
        argv[6] = log_level_str;
        argv[7] = NULL;
        execvp("afpfsd", argv);
        /* If exec fails */
        _exit(1);
    }

    /* Parent process */
    add_child(pid, socket_id, mountpoint);
    return 0;
}

static int handle_manager_command(int client_fd)
{
    char buffer[4096];
    struct afp_server_request_header *hdr;
    ssize_t n = read(client_fd, buffer, sizeof(buffer));

    if (n <= 0) {
        return -1;
    }

    hdr = (struct afp_server_request_header *)buffer;

    switch (hdr->command) {
    case AFP_SERVER_COMMAND_SPAWN_MOUNT: {
        struct afp_server_spawn_mount_request *req =
            (struct afp_server_spawn_mount_request *)buffer;

        if (n < (ssize_t)sizeof(*req)) {
            return -1;
        }

        if (start_mount_daemon(req->socket_id, req->mountpoint) < 0) {
            unsigned char result = AFP_SERVER_RESULT_ERROR;
            write(client_fd, &result, 1);
            return -1;
        }

        sleep(1);
        unsigned char result = AFP_SERVER_RESULT_OKAY;
        write(client_fd, &result, 1);
        break;
    }

    case AFP_SERVER_COMMAND_EXIT:
        cleanup_all_children();
        close(client_fd);
        return -2;  /* Signal to exit manager */

    case AFP_SERVER_COMMAND_PING: {
        unsigned char result = AFP_SERVER_RESULT_OKAY;
        write(client_fd, &result, 1);
        break;
    }

    case AFP_SERVER_COMMAND_STATUS: {
        /* Manager daemon: return a basic status message */
        struct afp_server_response response;
        char status_msg[1024];
        int count = 0;

        /* Count active mounts */
        for (struct manager_child *child = child_list; child; child = child->next) {
            count++;
        }

        if (count == 0) {
            snprintf(status_msg, sizeof(status_msg),
                     "afpfs-ng manager daemon running\n"
                     "No active mounts\n");
        } else {
            snprintf(status_msg, sizeof(status_msg),
                     "afpfs-ng manager daemon running\n"
                     "Active mounts: %d\n",
                     count);
        }

        response.result = AFP_SERVER_RESULT_OKAY;
        response.len = strlen(status_msg);
        write(client_fd, &response, sizeof(response));
        write(client_fd, status_msg, response.len);
        break;
    }

    default:
        /* Unknown command */
        break;
    }

    return 0;
}

static int run_manager_daemon(void)
{
    int listen_fd = startup_listener();
    struct sigaction sa;

    if (listen_fd < 0) {
        return -1;
    }

    /* Install SIGCHLD handler to immediately reap child processes */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    log_for_client(NULL, AFPFSD, LOG_NOTICE,
                   "Starting manager daemon on %s\n", commandfilename);

    while (1) {
        fd_set rds;
        FD_ZERO(&rds);
        FD_SET(listen_fd, &rds);
        struct timeval tv = {30, 0};
        int ret = select(listen_fd + 1, &rds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }

            break;
        }

        if (ret == 0) {
            /* Timeout - check for dead children */
            struct manager_child *child = child_list;

            while (child) {
                struct manager_child *next = child->next;
                int status;
                pid_t result = waitpid(child->pid, &status, WNOHANG);

                if (result > 0) {
                    remove_child(child->pid);
                }

                child = next;
            }

            continue;
        }

        if (FD_ISSET(listen_fd, &rds)) {
            struct sockaddr_un client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);

            if (client_fd < 0) {
                continue;
            }

            int result = handle_manager_command(client_fd);
            close(client_fd);

            if (result == -2) {
                /* Exit requested */
                break;
            }
        }
    }

    close_commands(listen_fd);
    cleanup_all_children();
    return 0;
}

int main(int argc, char *argv[])
{
    int option_index = 0;
    struct option long_options[] = {
        {"logmethod", 1, 0, 'l'},
        {"loglevel", 1, 0, 'v'},
        {"foreground", 0, 0, 'f'},
        {"debug", 0, 0, 'd'},
        {"socket-id", 1, 0, 's'},
        {"manager", 0, 0, 'm'},
        {0, 0, 0, 0},
    };
    int new_log_method = LOG_METHOD_SYSLOG;
    int log_level = LOG_NOTICE;
    int dofork = 1;
    int manager_mode = 0;
    /* getopt_long()'s return is int; specifying the variable to contain
     * this return value as char depends on endian-specific behavior,
     * breaking utterly on big endian (i.e., PowerPC)
     */
    int c;
    int command_fd = -1;
    const char *socket_id = NULL;

    while (1) {
        c = getopt_long(argc, argv, "dfhl:ms:v:",
                        long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'l':
            if (strncmp(optarg, "stdout", 6) == 0) {
                new_log_method = LOG_METHOD_STDOUT;
            } else if (strncmp(optarg, "syslog", 6) == 0) {
                new_log_method = LOG_METHOD_SYSLOG;
            } else {
                printf("Unknown log method %s\n", optarg);
                usage();
                return -1;
            }

            break;

        case 'f':
            dofork = 0;
            break;

        case 'd':
            dofork = 0;
            debug_mode = 1;
            new_log_method = LOG_METHOD_STDOUT;
            log_level = LOG_DEBUG;
            break;

        case 'm':
            manager_mode = 1;
            break;

        case 's':
            socket_id = optarg;
            break;

        case 'v': {
            int parsed_loglevel;

            if (parse_level(optarg, &parsed_loglevel) != 0) {
                printf("Unknown log level %s\n", optarg);
                usage();
                return -1;
            }

            log_level = parsed_loglevel;
            break;
        }

        case 'h':
        default:
            usage();
            return -1;
        }
    }

    /* Apply log settings early, before any daemon code or fork */
    fuse_set_log_method(new_log_method);
    fuse_set_log_level(log_level);
    current_log_method = new_log_method;
    current_log_level = log_level;

    /* If logging to stdout, enable line buffering for timely output */
    if (new_log_method & LOG_METHOD_STDOUT) {
        setvbuf(stdout, NULL, _IOLBF, 0);
    }

    /* Now register the client callback and initialize UAMs with logging ready */
    fuse_register_afpclient();

    if (init_uams() < 0) {
        return -1;
    }

    if (socket_id != NULL) {
        snprintf(commandfilename, sizeof(commandfilename), "%s", socket_id);
    } else {
        sprintf(commandfilename, "%s-%d", SERVER_FILENAME, (unsigned int) geteuid());
    }

    /* Mount daemons (not manager) should auto-shutdown when last volume unmounts */
    if (socket_id != NULL && !manager_mode) {
        afp_set_auto_shutdown_on_unmount(1);
    }

    if (remove_other_daemon() < 0)  {
        log_for_client(NULL, AFPFSD, LOG_NOTICE,
                       "Daemon is already running and alive\n");
        return -1;
    }

    if ((!dofork) || (fork() == 0)) {
        if (manager_mode) {
            return run_manager_daemon();
        }

        /* Run mount daemon */
        if ((command_fd = startup_listener()) < 0) {
            goto error;
        }

        log_for_client(NULL, AFPFSD, LOG_NOTICE,
                       "Starting up AFPFS version %s\n", AFPFS_VERSION);
        afp_main_loop(command_fd);
        close_commands(command_fd);
    }

    return 0;
error:
    printf("Could not start afpfsd\n");
    return -1;
}
