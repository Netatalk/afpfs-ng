/*
    Copyright (C) 1987-2002 Free Software Foundation, Inc.
    Copyright (C) 2007 Alex deVries <alexthepuffin@gmail.com>
    Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>

    This is based on readline's fileman.c example, which is very useful.
    The original fileman.c carries the following notice:

    This file is part of the GNU Readline Library, a library for
    reading lines of text with interactive input and history editing.

    The GNU Readline Library is free software; you can redistribute it
    and/or modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2, or
    (at your option) any later version.

    The GNU Readline Library is distributed in the hope that it will be
    useful, but WITHOUT ANY WARRANTY; without even the implied warranty
    of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    The GNU General Public License is often shipped with GNU software, and
    is generally kept in a file called COPYING or LICENSE.  If you do not
    have a copy of the license, write to the Free Software Foundation,
    59 Temple Place, Suite 330, Boston, MA 02111 USA.
*/

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#ifdef HAVE_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#elif defined(HAVE_LIBEDIT)
#include <editline/readline.h>
#include <histedit.h>
#endif
#include <getopt.h>
#include <ctype.h>
#include <signal.h>

#ifdef HAVE_LIBBSD
#include <bsd/string.h>
#endif

#include "afp.h"
#include "libafpclient.h"
#include "utils.h"
#include "cmdline_afp.h"
#include "cmdline_testafp.h"

static int running = 1;
static int loop_started = 0;

static pthread_cond_t connected_condition;
static pthread_cond_t loop_started_condition;

extern int com_testafp(char * arg);

static struct termios save_termios;

#ifndef whitespace
#define whitespace(c) (((c) == ' ') || ((c) == '\t'))
#endif

/* A structure which contains information on the commands this program
 *  *    can understand. */

typedef struct {
    char *name;          /* User printable name of the function. */
    int (*func)(char * arg); /* Function to call to do the job. */
    char *doc;           /* Documentation for this function.  */
    int thread;          /* whether to launch as a new thread */
} COMMAND;

void trigger_connected(void)
{
    pthread_cond_signal(&connected_condition);
}

static int tty_reset(int fd)
{
    if (tcsetattr(fd, TCSAFLUSH, &save_termios) < 0) {
        return -1;
    }

    return 0;
}


/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
static char *stripwhite(char * string)
{
    char *s, *t;

    for (s = string; whitespace(*s); s++);

    if (*s == 0) {
        return (s);
    }

    t = s + strlen(s) - 1;

    while (t > s && whitespace(*t)) {
        t--;
    }

    *++t = '\0';
    return s;
}

/* **************************************************************** */
/*                                                                  */
/*                  Interface to Readline Completion                */
/*                                                                  */
/* **************************************************************** */

static char *command_generator(const char *, int);

#if 0
static int remote_entries_num = 0;

static char *remote_generator(const char *text, int state)
{
    char *foo = malloc(255);
    remote_entries_num++;
    sprintf(foo, "Foo");

    if (remote_entries_num == 5) {
        return NULL;
    }

    return foo;
}

#endif

/* Attempt to complete on the contents of TEXT.  START and END bound the
   region of rl_line_buffer that contains the word to complete.  TEXT is
   the word to complete.  We can use the entire contents of rl_line_buffer
   in case we want to do some simple parsing.  Return the array of matches,
   or NULL if there aren't any. */
static char **filename_completion(const char *text,
                                  int start, __attribute__((unused)) int end)
{
    char **matches = NULL;

    /* If this word is at the start of the line, then it is a command
    to complete.  Otherwise it is the name of a file in the current
    directory. */
    if (start == 0) {
        matches = rl_completion_matches(text, command_generator);
    } else {
        /* This is where we'd do remote filename completion */
    }

    return (matches);
}

/* Tell the GNU Readline library how to complete.  We want to try to complete
   on command names if this is the first word in the line, or on filenames
   if not. */
static void initialize_readline(void)
{
    /* Allow conditional parsing of the ~/.inputrc file. */
    rl_readline_name = "afpfsd";
    /* Tell the completer that we want a crack first. */
    rl_attempted_completion_function = filename_completion;
#if 0
    rl_catch_signals = 1 ;
    rl_catch_sigwinch = 1 ;
    rl_set_signals() ;
#endif
}

/* The user wishes to quit using this program.  Just set DONE non-zero. */
static int com_quit(__attribute__((unused)) char *arg)
{
    cmdline_afp_exit();
    running = 0;
    return 0;
}

static int com_help(char *arg);

COMMAND commands[] = {
    { "cd", com_cd, "Change to directory DIR", 1 },
    { "chmod", com_chmod, "Change mode", 1 },
    { "connect", com_connect, "Connect to SERVER", 1 },
    { "copy", com_copy, "Copy FILE to NEWFILE", 1 },
    { "cp", com_copy, "Synonym for `copy'", 1 },
    { "delete", com_delete, "Delete FILE", 1 },
    { "df", com_statvfs, "Get volume space information", 1 },
    { "dir", com_dir, "List files in DIR", 1 },
    { "disconnect", com_disconnect, "Disconnect from the current server", 1 },
    { "exit", com_exit, "Detach from the current volume", 1 },
    { "get", com_get, "Retrieve the file FILENAME and store them locally", 1 },
    { "help", com_help, "Display this text", 0 },
    { "lcd", com_lcd, "Change local directory to DIR", 1 },
    { "lpwd", com_lpwd, "Print the current local working directory", 0 },
    { "ls", com_dir, "Synonym for `dir'", 1 },
    { "mkdir", com_mkdir, "Make directory DIRECTORY", 1 },
    { "mv", com_rename, "Rename FILE to NEWNAME", 1 },
    { "pass", com_pass, "Set the password", 1 },
    { "put", com_put, "Send a file to the server", 1 },
    { "pwd", com_pwd, "Print the current working directory on the server", 0 },
    { "quit", com_quit, "Quit", 0 },
    { "rename", com_rename, "Synonym for `mv'", 1 },
    { "rm", com_delete, "Delete FILE", 1 },
    { "rmdir", com_rmdir, "Remove directory DIRECTORY", 1 },
    { "status", com_status, "Get some server status", 1 },
    { "touch", com_touch, "Touch FILE", 1 },
    { "user", com_user, "Set the user", 1 },
    { "view", com_view, "View the contents of FILE", 1 },
    { "?", com_help, "Synonym for `help'", 0 },
#ifdef DEBUG
    { "test", test_urls, "AFP URL parsing tests", 1},
#endif
    { (char *)NULL, NULL, (char *)NULL, 0 }
};

/* Generator function for command completion.  STATE lets us know whether
   to start from scratch; without any state (i.e. STATE == 0), then we
   start at the top of the list. */
static char *command_generator(const char *text, int state)
{
    static int list_index, len;
    char *name;

    /* If this is a new word to complete, initialize now.  This includes
    saving the length of TEXT for efficiency, and initializing the index
    variable to 0. */
    if (!state) {
        list_index = 0;

        if (!text) {
            return NULL;  /* No text to match */
        }

        len = strnlen(text, ARG_LEN);
    }

    /* Return the next name which partially matches from the command list. */
    while ((name = commands[list_index].name)) {
        list_index++;

        if (strncmp(name, text, len) == 0) {
            return strdup(name);
        }
    }

    /* If no names matched, then return NULL. */
    return ((char *)NULL);
}

/* Print out help for ARG, or for all of the commands if ARG is
   not present. */
static int com_help(char *arg)
{
    register int i;
    int printed = 0;

    for (i = 0; commands[i].name; i++) {
        if (!*arg || (strcmp(arg, commands[i].name) == 0)) {
            printf("  %-12s  %s\n", commands[i].name, commands[i].doc);
            printed++;
        }
    }

    if (!printed) {
        printf("No commands match `%s'.  Possibilties are:\n", arg);

        for (i = 0; commands[i].name; i++) {
            /* Print in six columns. */
            if (printed == 6) {
                printed = 0;
                printf("\n");
            }

            printf("%s\t", commands[i].name);
            printed++;
        }

        if (printed) {
            printf("\n");
        }
    }

    return (0);
}

/* Look up NAME as the name of a command, and return a pointer to that
   command.  Return a NULL pointer if NAME isn't a command name. */
static COMMAND *find_command(char *name)
{
    int i;

    for (i = 0; commands[i].name; i++)
        if (strcmp(name, commands[i].name) == 0) {
            return (&commands[i]);
        }

    return ((COMMAND *)NULL);
}

/* Execute a command line. */
static int execute_line(char * line)
{
    int i;
    COMMAND *command;
    char *word;
    /* Isolate the command word. */
    i = 0;

    while (line[i] && whitespace(line[i])) {
        i++;
    }

    word = line + i;

    while (line[i] && !whitespace(line[i])) {
        i++;
    }

    if (line[i]) {
        line[i++] = '\0';
    }

    command = find_command(word);

    if (!command) {
        fprintf(stderr, "%s: No such command.\n", word);
        return (-1);
    }

    /* Get argument to command, if any. */
    while (whitespace(line[i])) {
        i++;
    }

    word = line + i;
    /* Call the function. */
    command->func(word);
    return 0;
}

void *cmdline_ui(__attribute__((unused)) void * other)
{
    char *line;
    char *s, s2[ARG_LEN];

    while (running)  {
        line = readline("afpcmd: ");

        if (!line) {
            return 0;
        }

        /* Remove leading and trailing whitespace from the line.
        Then, if there is anything left, add it to the history list
        and execute it. */
        s = stripwhite(line);
        strlcpy(s2, s, ARG_LEN);

        if (*s) {
            add_history(s);
            execute_line(s2);
        }

        free(line);
    }

    return 0;
}

static void ending(void)
{
    if (full_url == 0) {
        printf("Forced exit\n");
    }

    cmdline_afp_exit();
    tty_reset(STDIN_FILENO);
    exit(1);
}

void cmdline_forced_ending_hook(void)
{
    ending();
}

void earlyexit_handler(__attribute__((unused)) int signum)
{
    ending();
}

void cmdline_loop_started(void)
{
    loop_started = 1;
    pthread_cond_signal(&loop_started_condition);
}

static void usage(void)
{
    printf(
        "afpfs-ng %s - Apple Filing Protocol CLI client application\n"
        "afpcmd [-h] [-r] [-v loglevel] <afp url>\n"
        "Options:\n"
        "\t-h:          show this help message\n"
        "\t-r:          set the recursive flag\n"
        "\t-v loglevel: set log verbosity (debug, info, notice, warning, error)\n"
        "\turl:         an AFP url, in the form of:\n"
        "\t\t         afp://username;AUTH=uamname:password@server:548/volume/path\n"
        "\t             uamname can be a full UAM name or shorthand:\n"
        "\t             guest, clrtxt, randnum, 2wayrandnum, dhx, dhx2\n\n"
        "See the afpcmd(1) man page for more information.\n", AFPFS_VERSION
    );
}


int main(int argc, char *argv[])
{
    int option_index = 0;
    int c;
    int recursive = 0;
    int show_usage = 0;
    int log_level = LOG_NOTICE; /* Default log level */
    struct option long_options[] = {
        {"recursive", 0, 0, 'r'},
        {"loglevel", 1, 0, 'v'},
        {NULL, 0, NULL, 0},
    };
    char *url = NULL;

    while (1) {
        c = getopt_long(argc, argv, "hrv:",
                        long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            show_usage = 1;
            break;

        case 'r':
            recursive = 1;
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

        default:
            show_usage = 1;
            break;
        }
    }

    if (optind < argc) {
        url = argv[optind];
    }

    if (show_usage) {
        usage();
        exit(0);
    }

    tcgetattr(STDIN_FILENO, &save_termios);
    initialize_readline();
    cmdline_afp_setup_client();
    cmdline_set_log_level(log_level);
    afp_main_quick_startup(NULL);
    cmdline_afp_setup(recursive, url);
    signal(SIGINT, earlyexit_handler);
    cmdline_ui(NULL) ;
    tty_reset(STDIN_FILENO);
    exit(0);
}

