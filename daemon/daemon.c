/*
 *  daemon.c - Stateless daemon main loop
 *
 *  Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2026 Daniel Markstedt <daniel@mindani.net>
 *
 *  This is the main loop for afpsld (stateless daemon).
 */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>

#include "afp.h"
#include "dsi.h"
#include "afp_server.h"
#include "utils.h"
#include "daemon.h"
#include "commands.h"
#include "daemon_socket.h"

#define MAX_ERROR_LEN 1024
#define STATUS_LEN 1024

void afp_set_auto_disconnect_on_unmount(int enabled);

static int daemon_log_method = LOG_METHOD_SYSLOG;
static int daemon_log_min_rank = 2; /* Default rank: notice */

static int debug_mode = 0;
static char commandfilename[PATH_MAX];

int get_debug_mode(void)
{
    return debug_mode;
}

static void daemon_set_log_method(int new_method)
{
    daemon_log_method = new_method;
}

static void daemon_set_log_level(int loglevel)
{
    daemon_log_min_rank = loglevel_to_rank(loglevel);
}

static void daemon_log_for_client(void * priv,
                                  __attribute__((unused)) enum logtypes logtype,
                                  int loglevel, const char *message)
{
    struct daemon_client * c = priv;
    int type_rank = loglevel_to_rank(loglevel);

    if (type_rank < daemon_log_min_rank) {
        return; /* Filter out less-verbose messages */
    }

    if (c) {
        /* Thread-safe access to outgoing_string */
        pthread_mutex_lock(&c->command_string_mutex);

        /* Defensive check: ensure outgoing_string_len is within bounds */
        if (c->outgoing_string_len >= sizeof(c->outgoing_string)) {
            c->outgoing_string_len = 0;
            c->outgoing_string[0] = '\0';
        }

        size_t available = sizeof(c->outgoing_string) - c->outgoing_string_len;

        if (available > 1) {
            int written = snprintf(c->outgoing_string + c->outgoing_string_len,
                                   available,
                                   "%s\n", message);

            if (written > 0) {
                /* snprintf returns the number it tried to write, not what actually fit.
                 * We need to cap it to the available space (minus null terminator). */
                size_t actual_written;

                if ((size_t)written >= available) {
                    /* Truncation occurred - only (available-1) bytes were written */
                    actual_written = available - 1;
                } else {
                    actual_written = (size_t)written;
                }

                c->outgoing_string_len += actual_written;
            }
        }

        /* Always ensure null termination at the tracked position */
        if (c->outgoing_string_len < sizeof(c->outgoing_string)) {
            c->outgoing_string[c->outgoing_string_len] = '\0';
        }

        pthread_mutex_unlock(&c->command_string_mutex);
    } else {
        if (daemon_log_method & LOG_METHOD_SYSLOG) {
            syslog(loglevel, "%s", message);
        }

        if (daemon_log_method & LOG_METHOD_STDOUT) {
            printf("%s\n", message);
        }
    }
}

void daemon_forced_ending_hook(void)
{
    /* Disconnect from and clean up all client connections. */
    for (struct afp_server * s = get_server_base(); s; s = s->next) {
        if (s->connect_state == SERVER_STATE_CONNECTED) {
            for (int i = 0; i < s->num_volumes; i++) {
                struct afp_volume * volume = &s->volumes[i];

                if (volume->attached == AFP_VOLUME_ATTACHED) {
                    log_for_client(NULL, AFPFSD, LOG_NOTICE,
                                   "Disconnecting from volume %s",
                                   volume->volume_name);
                    afp_unmount_volume(volume);
                }
            }
        }
    }

    remove_all_clients();
}

int daemon_unmount_volume(struct afp_volume * volume)
{
    if (!volume) {
        return -1;
    }

    /* For stateless daemon, we just need to mark it as detached.
     * The actual AFP disconnect will be handled elsewhere. */
    return 0;
}


static int startup_listener(void)
{
    return daemon_socket_create(commandfilename, DAEMON_NUM_CLIENTS);
}

void close_commands(int command_fd)
{
    daemon_socket_close(command_fd, commandfilename);
}

static void usage(void)
{
    printf("Usage: afpsld [OPTION]\n"
           "  -l, --logmethod    Either 'syslog' or 'stdout'\n"
           "  -v, --loglevel     LOG_DEBUG|LOG_INFO|LOG_NOTICE|LOG_WARNING|LOG_ERR\n"
           "  -f, --foreground   Do not fork\n"
           "  -d, --debug        Do not fork, debug loglevel, logs to stdout\n"
           "Version %s\n", AFPFS_VERSION);
}

static struct libafpclient client = {
    .unmount_volume = daemon_unmount_volume,
    .log_for_client = daemon_log_for_client,
    .forced_ending_hook = daemon_forced_ending_hook,
    .scan_extra_fds = daemon_scan_extra_fds
};

static int daemon_register_afpclient(void)
{
    libafpclient_register(&client);
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
        {0, 0, 0, 0},
    };
    int new_log_method = LOG_METHOD_SYSLOG;
    int log_level = LOG_NOTICE;
    int dofork = 1;
    /* getopt_long()'s return is int; specifying the variable to contain
     * this return value as char depends on endian-specific behavior,
     * breaking utterly on big endian (i.e., PowerPC)
     */
    int c;
    int command_fd = -1;
    daemon_register_afpclient();
    /* Stateless daemon should keep server connections alive after volume detach
     * to allow browsing/attaching other volumes */
    afp_set_auto_disconnect_on_unmount(0);

    if (init_uams() < 0) {
        return -1;
    }

    /* Ignore SIGPIPE to prevent daemon from exiting when client disconnects */
    signal(SIGPIPE, SIG_IGN);

    while (1) {
        c = getopt_long(argc, argv, "dfhl:v:",
                        long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'l':
            if (strncmp(optarg, "stdout", 6) == 0) {
                daemon_set_log_method(LOG_METHOD_STDOUT);
            } else if (strncmp(optarg, "syslog", 6) == 0) {
                daemon_set_log_method(LOG_METHOD_SYSLOG);
            } else {
                printf("Unknown log method %s\n", optarg);
                usage();
            }

            break;

        case 'v': {
            int parsed_loglevel;

            if (string_to_log_level(optarg, &parsed_loglevel) != 0) {
                printf("Unknown log level %s\n", optarg);
                usage();
                return -1;
            }

            log_level = parsed_loglevel;
            break;
        }

        case 'f':
            dofork = 0;
            break;

        case 'd':
            dofork = 0;
            debug_mode = 1;
            new_log_method = LOG_METHOD_STDOUT;
            log_level = LOG_DEBUG;
            break;

        case 'h':
        default:
            usage();
            return -1;
        }
    }

    daemon_set_log_method(new_log_method);
    daemon_set_log_level(log_level);
    snprintf(commandfilename, sizeof(commandfilename), "%s-%d",
             SERVER_SL_SOCKET_PATH, geteuid());

    if ((!dofork) || (fork() == 0)) {
        if ((command_fd = startup_listener()) < 0) {
            goto error;
        }

        log_for_client(NULL, AFPFSD, LOG_NOTICE,
                       "Starting up AFPFS version %s", AFPFS_VERSION);
        afp_main_loop(command_fd);
        close_commands(command_fd);
    }

    return 0;
error:
    printf("Could not start afpsld\n");
    return -1;
}
