/*
 *  loop.c
 *
 *  Copyright (C) 2007 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "afp.h"
#include "dsi.h"
#include "utils.h"

#define SIGNAL_TO_USE SIGUSR2

/* This allows for main loop debugging */
#ifdef DEBUG
#define DEBUG_LOOP 1
#endif

static unsigned char exit_program = 0;

static pthread_t ending_thread = (pthread_t)NULL;
static pthread_t main_thread = (pthread_t)NULL;

static int loop_started = 0;
static pthread_cond_t loop_started_condition = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t loop_started_mutex = PTHREAD_MUTEX_INITIALIZER;


void trigger_exit(void)
{
    exit_program = 1;
}

void termination_handler(int signum)
{
    switch (signum) {
    case SIGINT:
    case SIGTERM:
        trigger_exit();
        break;

    default:
        break;
    }

    signal(SIGNAL_TO_USE, termination_handler);
}

#define max(a,b) (((a)>(b)) ? (a) : (b))

static fd_set rds;
static int max_fd = 0;

static void add_fd(int fd)
{
    FD_SET(fd, &rds);

    if ((fd + 1) > max_fd) {
        max_fd = fd + 1;
    }
}

static void rm_fd(int fd)
{
    int i;
    FD_CLR(fd, &rds);

    for (i = max_fd; i >= 0; i--)
        if (FD_ISSET(i, &rds)) {
            max_fd = i;
            break;
        }

    max_fd++;
}

void signal_main_thread(void)
{
    if (main_thread) {
        pthread_kill(main_thread, SIGNAL_TO_USE);
    }
}

static int ending = 0;
void *just_end_it_now(__attribute__((unused)) void * ignore)
{
    if (ending) {
        return NULL;
    }

    ending = 1;

    if (libafpclient->forced_ending_hook) {
        libafpclient->forced_ending_hook();
    }

    exit_program = 2;
    signal_main_thread();
    return NULL;
}

/*This is a hack to handle a problem where the first pthread_kill doesnt' work*/
static unsigned char firsttime = 0;
void add_fd_and_signal(int fd)
{
    add_fd(fd);
    signal_main_thread();

    if (!firsttime) {
        firsttime = 1;
        signal_main_thread();
    }
}

void rm_fd_and_signal(int fd)
{
    rm_fd(fd);
    signal_main_thread();
}

void loop_disconnect(struct afp_server *s)
{
    if (s->connect_state != SERVER_STATE_CONNECTED) {
        return;
    }

    rm_fd_and_signal(s->fd);
    /* Handle disconnect */
    close(s->fd);
    s->connect_state = SERVER_STATE_DISCONNECTED;
    s->need_resume = 1;
}

static int process_server_fds(fd_set * set, __attribute__((unused)) int max_fd,
                              int **onfd)
{
    struct afp_server * s;
    int ret;
    s  = get_server_base();

    for (; s; s = s->next) {
        if (s->next == s) {
            printf("Danger, recursive loop\n");
        }

        if (FD_ISSET(s->fd, set)) {
            ret = dsi_recv(s);
            *onfd = &s->fd;

            if (ret == -1) {
                loop_disconnect(s);
                return -1;
            }

            return 1;
        }
    }

    return 0;
}

static void deal_with_server_signals(__attribute__((unused)) fd_set *set,
                                     __attribute__((unused)) int * max_fd)
{
    if (exit_program == 1) {
        pthread_create(&ending_thread, NULL, just_end_it_now, NULL);
    }
}

void afp_wait_for_started_loop(void)
{
    if (loop_started) {
        return;
    }

    pthread_cond_wait(&loop_started_condition, &loop_started_mutex);
}

static void *afp_main_quick_startup_thread(__attribute__((unused)) void * other)
{
    afp_main_loop(-1);
    return NULL;
}


int afp_main_quick_startup(pthread_t * thread)
{
    pthread_t loop_thread;
    pthread_create(&loop_thread, NULL, afp_main_quick_startup_thread, NULL);

    if (thread) {
        memcpy(thread, &loop_thread, sizeof(pthread_t));
    }

    return 0;
}


int afp_main_loop(int command_fd)
{
    fd_set ords, oeds;
    struct timespec tv;
    int ret;
    int fderrors = 0;
    sigset_t sigmask, orig_sigmask;
    main_thread = pthread_self();
    FD_ZERO(&rds);

    if (command_fd >= 0) {
        add_fd(command_fd);
    }

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGNAL_TO_USE);
    sigprocmask(SIG_BLOCK, &sigmask, &orig_sigmask);
    signal(SIGNAL_TO_USE, termination_handler);
    signal(SIGTERM, termination_handler);
    signal(SIGINT, termination_handler);
#ifdef DEBUG_LOOP
    printf("afp_main_loop -- Starting up loop\n");
#endif

    while (1) {
#ifdef DEBUG_LOOP
        printf("afp_main_loop -- Setting new fds\n");
        {
            int j;

            for (j = 0; j < 16; j++) if (FD_ISSET(j, &rds)) {
                    printf("afp_main_loop -- fd %d is set\n", j);
                }
        }
#endif
        ords = rds;
        oeds = rds;

        if (loop_started) {
            tv.tv_sec = 30;
            tv.tv_nsec = 0;
        } else {
            tv.tv_sec = 0;
            tv.tv_nsec = 0;
        }

#ifdef DEBUG_LOOP
        printf("afp_main_loop -- Starting new select\n");
#endif

        // Check exit conditions BEFORE pselect
        if (exit_program == 2) {
            break;
        }

        if (exit_program == 1) {
            pthread_create(&ending_thread, NULL, just_end_it_now, NULL);
            continue;
        }

        pthread_sigmask(SIG_SETMASK, &orig_sigmask, NULL);
        ret = pselect(max_fd, &ords, NULL, &oeds, &tv, &orig_sigmask);
        int saved_errno = errno;  // Save errno immediately
        pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
        errno = saved_errno;  // Restore errno after sigmask operations

        // Check exit conditions first after pselect returns
        if (exit_program == 2) {
            break;
        }

        if (exit_program == 1) {
            pthread_create(&ending_thread, NULL, just_end_it_now, NULL);
            continue;
        }

        // Handle select errors with proper signal mask state
        if (ret < 0) {
            if (errno == EINTR) {
                deal_with_server_signals(&rds, &max_fd);
                continue;
            }

            perror("afp_main_loop select");

            switch (errno) {
            case EBADF:
#ifdef DEBUG_LOOP
                printf("afp_main_loop -- Dealing with a bad file descriptor\n");
#endif

                if (fderrors > 100) {
                    log_for_client(NULL, AFPFSD, LOG_ERR,
                                   "Too many fd errors, exiting\n");
                    break;
                }

                fderrors++;
                continue;

            default:
#ifdef DEBUG_LOOP
                printf("afp_main_loop -- Dealing with some other error, %d\n",
                       errno);
#endif

                if (libafpclient->scan_extra_fds) {
#ifdef DEBUG_LOOP
                    printf("afp_main_loop -- Other error\n");
#endif
                    ret = libafpclient->scan_extra_fds(
                              command_fd, &ords, &max_fd);
                }

                continue;
            }

            continue;
        }

        fderrors = 0;

        if (ret == 0) {
            if (!loop_started) {
                pthread_mutex_lock(&loop_started_mutex);
                loop_started = 1;
                pthread_cond_signal(&loop_started_condition);
                pthread_mutex_unlock(&loop_started_mutex);

                if (libafpclient->loop_started) {
                    libafpclient->loop_started();
                }
            }
        } else {
            int *onfd;
            fderrors = 0;

            /* Skip processing FDs if we're shutting down to avoid race conditions */
            if (exit_program >= 1) {
                continue;
            }

            switch (process_server_fds(&ords, max_fd, &onfd)) {
            case -1:
#ifdef DEBUG_LOOP
                printf("afp_main_loop --  error returning from process_server_fds()\n");
#endif
                goto error;

            case 1:
#ifdef DEBUG_LOOP
                printf("afp_main_loop -- success returning from process_server_fds()\n");
#endif
                continue;
            }

            if (libafpclient->scan_extra_fds) {
#ifdef DEBUG_LOOP
                printf("afp_main_loop --  Scanning client fds\n");
#endif

                if (libafpclient->scan_extra_fds(
                            command_fd, &ords, &max_fd) > 0) {
                    continue;
                }
            }
        }
    }

#ifdef DEBUG_LOOP
    printf("afp_main_loop -- done with loop altogether\n");
#endif
error:

    if (ending_thread != (pthread_t)NULL) {
        pthread_detach(ending_thread);
    }

    return -1;
}
