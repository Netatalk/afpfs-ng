/*
 *  daemon_client.c
 *
 *  Copyright (C) 2008 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2026 Daniel Markstedt <daniel@mindani.net>
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <getopt.h>
#include <signal.h>

#include "afp.h"
#include "dsi.h"
#include "afpfsd.h"
#include "utils.h"
#include "daemon.h"
#include "uams_def.h"
#include "codepage.h"
#include "libafpclient.h"
#include "map_def.h"
#include "daemon_client.h"
#include "commands.h"

static struct daemon_client client_pool[DAEMON_NUM_CLIENTS];

/* Used to protect the pool searching, creation and deletion */
pthread_mutex_t client_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

int remove_client(struct daemon_client ** toremove)
{
    int ret = 0;

    if ((toremove == NULL) || (*toremove == NULL)) {
        return -1;
    }

    pthread_mutex_lock(&client_pool_mutex);

    /* Go find the client */
    for (int i = 0; i < DAEMON_NUM_CLIENTS; i++) {
        if (*toremove == &client_pool[i]) {
            /* Destroy mutexes before marking as unused */
            pthread_mutex_destroy(&client_pool[i].command_string_mutex);
            pthread_mutex_destroy(&client_pool[i].processing_mutex);
            client_pool[i].used = 0;
            /* Note: processing_thread is created DETACHED (PTHREAD_CREATE_DETACHED)
             * in process_command(), so we cannot and should not try to join it.
             * Detached threads clean up automatically when they finish. */
            goto done;
        }
    }

    ret = -1;
done:
    pthread_mutex_unlock(&client_pool_mutex);
    return ret;
}

void remove_all_clients(void)
{
    pthread_mutex_lock(&client_pool_mutex);

    for (int i = 0; i < DAEMON_NUM_CLIENTS; i++) {
        if (client_pool[i].used) {
            pthread_mutex_destroy(&client_pool[i].command_string_mutex);
            pthread_mutex_destroy(&client_pool[i].processing_mutex);
        }

        client_pool[i].used = 0;
    }

    pthread_mutex_unlock(&client_pool_mutex);
}


int continue_client_connection(struct daemon_client * c)
{
    if (c->toremove) {
        c->pending = 0;
        remove_client(&c);
        return 0;
    }

    c->incoming_size = 0;
    add_fd_and_signal(c->fd);
    return 0;
}

int close_client_connection(struct daemon_client * c)
{
    c->a = &c->incoming_string[0];
    c->incoming_size = 0;

    if ((!c) ||
            (c->fd == 0)) {
        return -1;
    }

    rm_fd_and_signal(c->fd);
    close(c->fd);
    remove_client(&c);
    return 0;
}


static int add_client(int fd)
{
    struct daemon_client * c;
    pthread_mutex_lock(&client_pool_mutex);

    for (int i = 0; i < DAEMON_NUM_CLIENTS; i++) {
        c = &client_pool[i];

        if (c->used == 0) {
            goto found;
        }
    }

    pthread_mutex_unlock(&client_pool_mutex);
    return -1;
found:
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->command_string_mutex, NULL);
    pthread_mutex_init(&c->processing_mutex, NULL);
    c->fd = fd;
    c->a = &c->incoming_string[0];
    c->incoming_size = 0;
    c->used = 1;
    pthread_mutex_unlock(&client_pool_mutex);
    return 0;
}

/* Returns:
 * 0: Should continue
 * -1: Done with fd
 *
 */

static int process_client_fds(fd_set * set, __attribute__((unused)) int max_fd,
                              struct daemon_client **found)
{
    struct daemon_client * c;
    int ret;
    *found = NULL;
    pthread_mutex_lock(&client_pool_mutex);

    for (int i = 0; i < DAEMON_NUM_CLIENTS; i++) {
        c = &client_pool[i];

        if ((c->used) && (FD_ISSET(c->fd, set))) {
            goto found;
        }
    }

    /* We never found it */
    pthread_mutex_unlock(&client_pool_mutex);
    return 0;
found:
    pthread_mutex_unlock(&client_pool_mutex);

    if (found) {
        *found = c;
    }

    ret = process_command(c);

    if (ret == 0) {
        return 0;
    }

    if (ret < 0) {
        return -1;
    }

    return 1;
}

int daemon_scan_extra_fds(int command_fd, fd_set * set, int *max_fd)
{
    struct sockaddr_un new_addr;
    socklen_t new_len = sizeof(struct sockaddr_un);
    struct daemon_client * found;
    int ret;

    if (FD_ISSET(command_fd, set)) {
        int new_fd =
            accept(command_fd,
                   (struct sockaddr *) &new_addr, &new_len);

        if (new_fd >= 0) {
            if (add_client(new_fd) < 0) {
                log_for_client(NULL, AFPFSD, LOG_WARNING,
                               "Client pool full (%d), rejecting connection",
                               DAEMON_NUM_CLIENTS);
                close(new_fd);
                return 0;
            }

            add_fd_and_signal(new_fd);

            if ((new_fd + 1) > *max_fd) {
                *max_fd = new_fd + 1;
            }
        }

        return 0;
    }

    ret = process_client_fds(set, *max_fd, &found);

    switch (ret) {
    case 2: /* continue reading */
    case 0: /* clear it and continue */
        if (found) {
            FD_CLR(found->fd, set);
        }

        return -1;

    case -1: /* we're done with found->fd */
        if (found) {
            rm_fd_and_signal(found->fd);
            close(found->fd);
            remove_client(&found);
        }

        return -1;

    case 1: /* handled */
        return 1;

    default:
        /* unknown fd */
        sleep(10);
        return -1;
    }
}


unsigned int send_command(struct daemon_client * c,
                          unsigned int len, const char *data)
{
    unsigned int total = 0;
    int ret;

    while (total < len) {
        ret = write(c->fd, data + total, len - total);

        if (ret < 0) {
            perror("Writing");
            return -1;
        }

        total += ret;
    }

    return total;
}

void remove_command(struct daemon_client * c)
{
    pthread_mutex_unlock(&c->command_string_mutex);
}
