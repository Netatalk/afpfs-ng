/*
    Copyright (C) 1987-2002 Free Software Foundation, Inc.
    Copyright (C) 2007 Alex deVries <alexthepuffin@gmail.com>
    Copyright (C) 2024-2025 Daniel Markstedt <daniel@mindani.net>

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

#include "afp.h"
#include "afpsl.h"
#include "map_def.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <ctype.h>

#ifdef HAVE_LIBBSD
#include <bsd/string.h>
#endif

#include "libafpclient.h"
#include "utils.h"
#include "cmdline_afp.h"
#include "cmdline_main.h"

static char curdir[AFP_MAX_PATH];
static struct afp_url url;

int full_url = 0;

#define DEFAULT_DIRECTORY "/"

/* Stateless library uses opaque handles instead of direct pointers */
static volumeid_t vol_id = NULL;
static int connected = 0;  /* Track connection state */

static int recursive_get(char * path);

static int escape_paths(char * outgoing1, char * outgoing2, char * incoming)
{
    char *writeto = outgoing1;
    int inquote = 0, inescape = 0, donewith1 = 0;
    char *p = incoming;

    if ((outgoing1 == NULL) || (strlen(incoming) == 0)) {
        goto error;
    }

    memset(outgoing1, 0, AFP_MAX_PATH);

    if (outgoing2) {
        memset(outgoing2, 0, AFP_MAX_PATH);
    }

    for (p = incoming; p < incoming + strlen(incoming); p++) {
        if (*p == '"') {
            if (inescape) {
                inescape = 0;
                goto add;
            } else if (inquote) {
                inquote = 0;
                continue;
            } else {
                inquote = 1;
                continue;
            }
        }

        if (*p == ' ') {
            if (inescape) {
                inescape = 0;
                goto add;
            } else if (inquote) {
                goto add;
            } else if ((donewith1 == 1) || (outgoing2 == NULL)) {
                goto out;
            }

            writeto = outgoing2;
            donewith1 = 1;
            continue;
        }

        if (*p == '\\' && inescape == 0) {
            inescape = 1;
            continue;
        } else if (inescape) {
            inescape = 0;
            goto add;
        }

add:
        *writeto = *p;
        writeto++;
    }

out:

    if ((outgoing2 != NULL) && (donewith1 == 0)) {
        goto error;
    }

    return 0;
error:
    return -1;
}

static unsigned int tvdiff(struct timeval * starttv, struct timeval * endtv)
{
    unsigned int d;
    d = (endtv->tv_sec - starttv->tv_sec) * 1000;
    d += (endtv->tv_usec - starttv->tv_usec) / 1000;
    return d;
}

static void printdiff(struct timeval * starttv, struct timeval *endtv,
                      unsigned long long *amount_written)
{
    unsigned int diff;
    unsigned long long kb_written;
    diff = tvdiff(starttv, endtv);
    float frac = ((float) diff) / 1000.0; /* Now in seconds */
    printf("Transferred %lld bytes in ", *amount_written);
    printf("%.3f seconds. ", frac);
    /* Now calculate the transfer rate */
    kb_written = (*amount_written / 1000);
    float rate = (kb_written) / frac;
    printf("(%.0f kB/s)\n", rate);
}

static int cmdline_getpass(void)
{
    char *passwd;

    if (strcmp(url.password, "-") == 0) {
        passwd = getpass("Password:");
        strlcpy(url.password, passwd, AFP_MAX_PASSWORD_LEN);
    }

    return 0;
}


static int get_server_path(char * filename, char * server_fullname)
{
    int result;

    if (filename[0] != '/') {
        if (strlen(curdir) == 1) {
            result = snprintf(server_fullname, AFP_MAX_PATH, "/%s", filename);
        } else {
            result = snprintf(server_fullname, AFP_MAX_PATH, "%s/%s", curdir, filename);
        }

        if (result >= AFP_MAX_PATH || result < 0) {
            fprintf(stderr,
                    "Error: Path exceeds maximum length or other error occurred.\n");
            return -1;
        }
    } else {
        result = snprintf(server_fullname, AFP_MAX_PATH, "%s", filename);
    }

    if (result >= AFP_MAX_PATH || result < 0) {
        return -1;
    }

    return 0;
}

static void print_file_details_basic(struct afp_file_info_basic * p)
{
    struct tm * mtime;
    time_t t;
#define DATE_LEN 32
    char datestr[DATE_LEN];
    char mode_str[11];
    uint32_t mode = p->unixprivs.permissions;

    snprintf(mode_str, sizeof(mode_str), "----------");

    t = p->modification_date;
    mtime = localtime(&t);

    /* Check if directory based on mode */
    if (S_ISDIR(mode)) {
        mode_str[0] = 'd';
    }

    if (mode & S_IRUSR) {
        mode_str[1] = 'r';
    }

    if (mode & S_IWUSR) {
        mode_str[2] = 'w';
    }

    if (mode & S_IXUSR) {
        mode_str[3] = 'x';
    }

    if (mode & S_IRGRP) {
        mode_str[4] = 'r';
    }

    if (mode & S_IWGRP) {
        mode_str[5] = 'w';
    }

    if (mode & S_IXGRP) {
        mode_str[6] = 'x';
    }

    if (mode & S_IROTH) {
        mode_str[7] = 'r';
    }

    if (mode & S_IWOTH) {
        mode_str[8] = 'w';
    }

    if (mode & S_IXOTH) {
        mode_str[9] = 'x';
    }

    strftime(datestr, DATE_LEN, "%F %H:%M", mtime);
    printf("%s %6lld %s %s\n", mode_str, p->size, datestr, p->name);
}

/* connect_volume() and server_subconnect() removed - functionality moved to com_connect() */

int com_pass(char * arg)
{
    if ((strlen(arg) == 0) || (strcmp(arg, "-"))) {
        getpass("Password: ");
        return -1;
    }

    printf("Password set.\n");
    strlcpy(url.password, arg, AFP_MAX_PASSWORD_LEN);
    return 0;
}


int com_user(char * arg)
{
    if (strlen(arg) == 0) {
        printf("You must specify a user\n");
        return -1;
    }

    strlcpy(url.username, arg, AFP_MAX_PASSWORD_LEN);
    printf("username is now %s\n", url.username);
    return 0;
}

int com_disconnect(__attribute__((unused)) char * arg)
{
    if (!connected) {
        printf("You're not connected yet to a server\n");
        goto error;
    }

    if (afp_sl_detach(&vol_id, NULL)) {
        printf("Error detaching from volume\n");
    }

    vol_id = NULL;
    connected = 0;
    snprintf(curdir, AFP_MAX_PATH, "/");
    printf("Disconnected\n");
    return 0;
error:
    return -1;
}


int com_connect(char * arg)
{
    struct afp_url tmpurl;
    char mesg[MAX_ERROR_LEN];
    int error = 0;
    unsigned int uam_mask;
    serverid_t server_id;  /* Not saved, only used during connection */

    if (!arg) {
        printf("You must specify a server name or URL\n");
        goto error_out;
    }

    if (connected) {
        printf("You're already connected to a server\n");
        goto error_out;
    }

    afp_default_url(&tmpurl);

    /* First, try to parse the URL */

    if (afp_parse_url(&tmpurl, arg, 0) != 0) {
        /* Okay, this isn't a real URL */
        printf("Could not parse url, let me see if this is a server name...\n");

        if (gethostbyname(arg)) {
            memcpy(&url.servername, arg, AFP_SERVER_NAME_LEN);
        } else {
            printf("Cannot understand server name or url %s\n", arg);
            return -1;
        }
    } else {
        /* Preserve credentials from previous session if not specified in new URL */
        if (tmpurl.username[0] == '\0' && url.username[0] != '\0') {
            strlcpy(tmpurl.username, url.username, AFP_MAX_USERNAME_LEN);
        }

        if (tmpurl.password[0] == '\0' && url.password[0] != '\0') {
            strlcpy(tmpurl.password, url.password, AFP_MAX_PASSWORD_LEN);
        }

        if (tmpurl.uamname[0] == '\0' && url.uamname[0] != '\0') {
            strlcpy(tmpurl.uamname, url.uamname, sizeof(url.uamname));
        }

        url = tmpurl;
    }

    cmdline_getpass();

    /* Determine UAM mask */
    if (strlen(url.uamname) > 0) {
        if ((uam_mask = find_uam_by_name(url.uamname)) == 0) {
            printf("I don't know about UAM %s\n", url.uamname);
            goto error_out;
        }
    } else {
        uam_mask = default_uams_mask();
    }

    /* Connect to server via stateless library */
    if (afp_sl_connect(&url, uam_mask, &server_id, mesg, &error)) {
        printf("Could not connect to server: %s\n", mesg);
        goto error_out;
    }

    printf("Connected to server %s\n", url.servername);

    /* Attach to volume if specified */
    if (strlen(url.volumename) > 0) {
        unsigned int volume_options = VOLUME_EXTRA_FLAGS_NO_LOCKING;

        if (afp_sl_attach(&url, volume_options, &vol_id)) {
            printf("Could not attach to volume %s\n", url.volumename);
            goto error_out;
        }

        printf("[DEBUG] com_connect: after afp_sl_attach, vol_id=%p\n", (void*)vol_id);
        printf("Attached to volume %s\n", url.volumename);
        connected = 1;
    } else {
        printf("Connected, but no volume specified. Use 'cd <volume>' to attach to a volume.\n");
    }

    return 0;

error_out:
    return -1;
}


int com_dir(char * arg)
{
    if (!arg) {
        arg = "";
    }

    struct afp_file_info_basic *filebase = NULL;
    unsigned int numfiles = 0;
    int eod = 0;
    char path[AFP_MAX_PATH];
    char dir_path[AFP_MAX_PATH];

    printf("[DEBUG] com_dir: entry, arg='%s'\n", arg);

    if (!connected) {
        printf("You're not connected to a volume\n");
        printf("Use 'connect afp://server/volume' to connect.\n");
        goto error;
    }

    /* If an argument is provided, use it; otherwise use current directory */
    if (arg[0] != '\0') {
        if (escape_paths(path, NULL, arg)) {
            printf("Invalid path\n");
            goto error;
        }

        /* Handle "." as the current directory */
        if (strcmp(path, ".") == 0) {
            strlcpy(dir_path, curdir, AFP_MAX_PATH);
        } else {
            get_server_path(path, dir_path);
        }
    } else {
        strlcpy(dir_path, curdir, AFP_MAX_PATH);
    }

    /* Use stateless library to read directory */
    printf("[DEBUG] com_dir: vol_id=%p, calling afp_sl_readdir for path '%s'\n", (void*)vol_id, dir_path);
    if (afp_sl_readdir(&vol_id, dir_path, NULL, 0, 100, &numfiles, &filebase, &eod)) {
        printf("Could not read directory\n");
        printf("[DEBUG] com_dir: afp_sl_readdir failed\n");
        goto error;
    }

    printf("[DEBUG] com_dir: afp_sl_readdir success, numfiles=%d\n", numfiles);

    if (numfiles == 0) {
        printf("[DEBUG] com_dir: no files, goto out\n");
        goto out;
    }

    printf("[DEBUG] com_dir: printing %d files\n", numfiles);
    for (unsigned int i = 0; i < numfiles; i++) {
        print_file_details_basic(&filebase[i]);
    }

    free(filebase);
out:
    printf("[DEBUG] com_dir: returning 0 (success)\n");
    return 0;
error:
    printf("[DEBUG] com_dir: returning -1 (error)\n");
    return -1;
}


/* STUB: Requires afp_sl_creat() - not yet implemented */
int com_touch(char * arg)
{
    (void)arg; /* unused */
    printf("touch command not yet implemented via stateless library\n");
    printf("(requires afp_sl_creat)\n");
    return -1;
}

/* STUB: Requires afp_sl_chmod() - not yet implemented */
int com_chmod(char * arg)
{
    (void)arg; /* unused */
    printf("chmod command not yet implemented via stateless library\n");
    printf("(requires afp_sl_chmod)\n");
    return -1;
}


/* STUB: Requires afp_sl_write(), afp_sl_creat(), afp_sl_chmod() - not yet implemented */
int com_put(char *arg)
{
    (void)arg; /* unused */
    printf("put command not yet implemented via stateless library\n");
    printf("(requires afp_sl_write, afp_sl_creat, afp_sl_chmod)\n");
    return -1;
}

static int retrieve_file(char * arg, int fd, int silent,
                         struct stat *stat, unsigned long long *amount_written)
{
    int ret = 0;
    unsigned int fileid;
    char path[PATH_MAX];
    unsigned long long offset = 0;
#define BUF_SIZE 102400
    unsigned int size = BUF_SIZE;
    char buf[BUF_SIZE];
    unsigned int received, eof = 0;
    unsigned long long total = 0;
    struct timeval starttv, endtv;
    *amount_written = 0;

    if (!connected) {
        printf("You're not connected to a volume\n");
        goto error;
    }

    get_server_path(arg, path);
    gettimeofday(&starttv, NULL);

    /* Get file attributes using stateless library */
    if (afp_sl_stat(&vol_id, path, NULL, stat)) {
        printf("Could not get file attributes for file %s\n", path);
        goto error;
    }

    /* Open file using stateless library */
    if (afp_sl_open(&vol_id, path, NULL, &fileid, O_RDONLY)) {
        printf("Could not open %s on server\n", arg);
        goto error;
    }

    /* Read file in chunks */
    while (!eof) {
        memset(buf, 0, BUF_SIZE);
        ret = afp_sl_read(&vol_id, fileid, 0, offset, size, &received, &eof, buf);

        if (ret) {
            printf("Error reading file\n");
            break;
        }

        if (received == 0) {
            break;
        }

        total += write(fd, buf, received);
        offset += received;
    }

    if (fd > 1) {
        close(fd);
    }

    /* Close file using stateless library */
    afp_sl_close(&vol_id, fileid);

    if (silent == 0) {
        gettimeofday(&endtv, NULL);
        printdiff(&starttv, &endtv, &total);
    }

    *amount_written = total;
    return 0;
error:
    return -1;
}

static int com_get_file(char * arg, int silent,
                        unsigned long long *total)
{
    int fd;
    struct stat stat;
    char *localfilename;
    char filename[AFP_MAX_PATH];
    char getattr_path[AFP_MAX_PATH];

    if (!connected) {
        printf("You're not connected to a volume\n");
        goto error;
    }

    if ((escape_paths(filename, NULL, arg))) {
        printf("expecting format: get <filename>\n");
        goto error;
    }

    localfilename = basename(filename);
    printf("    Getting file %s\n", filename);
    get_server_path(filename, getattr_path);

    /* Get file attributes using stateless library */
    if (afp_sl_stat(&vol_id, getattr_path, NULL, &stat)) {
        printf("Could not get attributes for file \"%s\"\n", filename);
        goto error;
    }

    fd = open(localfilename, O_CREAT | O_TRUNC | O_RDWR, stat.st_mode);

    if (fd < 0) {
        printf("Failed to open \"%s\" for writing\n", localfilename);
        perror("Opening local file");
        goto error;
    }

    if (fchmod(fd, stat.st_mode) < 0) {
        perror("Setting file mode");
        /* Non-fatal error, continue */
    }

    if (fchown(fd, stat.st_uid, stat.st_gid) < 0) {
        perror("Setting file ownership");
        /* Non-fatal error, continue */
    }

    retrieve_file(filename, fd, silent, &stat, total);
    close(fd);
    return 0;
error:
    return -1;
}

int com_get(char *arg)
{
    unsigned long long amount_written;
    char newpath[AFP_MAX_PATH];

    if (!connected) {
        printf("You're not connected to a volume\n");
        goto error;
    }

    if ((arg[0] == '-') && (arg[1] == 'r') && (arg[2] == ' ')) {
        arg += 3;

        while ((arg) && (isspace(arg[0]))) {
            arg++;
        }

        int result = snprintf(newpath, AFP_MAX_PATH, "%s/%s", curdir, arg);

        if (result >= AFP_MAX_PATH || result < 0) {
            fprintf(stderr,
                    "Error: Path exceeds maximum length or other error occurred.\n");
            goto error;
        }

        return recursive_get(newpath);
    } else {
        return com_get_file(arg, 0, &amount_written);
    }

error:
    return -1;
}


int com_view(char * arg)
{
    unsigned long long amount_written;
    char filename[AFP_MAX_PATH];
    struct stat stat;

    if (!connected) {
        printf("You're not connected to a volume\n");
        goto error;
    }

    if ((escape_paths(filename, NULL, arg))) {
        printf("expecting format: view <filename>\n");
        goto error;
    }

    printf("Viewing: \"%s\"\n", filename);
    retrieve_file(filename, fileno(stdout), 1, &stat, &amount_written);
    return 0;
error:
    return -1;
}

/* STUB: Requires afp_sl_rename() - not yet implemented */
int com_rename(char * arg)
{
    (void)arg; /* unused */
    printf("mv/rename command not yet implemented via stateless library\n");
    printf("(requires afp_sl_rename)\n");
    return -1;
}

/* STUB: Requires afp_sl_write(), afp_sl_creat() - not yet implemented */
int com_copy(char * arg)
{
    (void)arg; /* unused */
    printf("cp/copy command not yet implemented via stateless library\n");
    printf("(requires afp_sl_write, afp_sl_creat)\n");
    return -1;
}
/* STUB: Requires afp_sl_unlink() - not yet implemented */
int com_delete(char *arg)
{
    (void)arg; /* unused */
    printf("rm/delete command not yet implemented via stateless library\n");
    printf("(requires afp_sl_unlink)\n");
    return -1;
}
/* STUB: Requires afp_sl_mkdir() - not yet implemented */
int com_mkdir(char *arg)
{
    (void)arg; /* unused */
    printf("mkdir command not yet implemented via stateless library\n");
    printf("(requires afp_sl_mkdir)\n");
    return -1;
}
/* STUB: Requires afp_sl_rmdir() - not yet implemented */
int com_rmdir(char *arg)
{
    (void)arg; /* unused */
    printf("rmdir command not yet implemented via stateless library\n");
    printf("(requires afp_sl_rmdir)\n");
    return -1;
}

/* STUB: Requires server handle - not yet implemented */
int com_status(__attribute__((unused)) char * arg)
{
    printf("status command not yet implemented via stateless library\n");
    return -1;
}

static void print_size(unsigned long l)
{
    if (l > (1073741824)) {
        printf("%4ldTb", l / 1073741824);
        return;
    }

    if (l > (1048576)) {
        printf("%4ldGb", l / 1048576);
        return;
    }

    if (l > (1024)) {
        printf("%4ldMb", l >> 10);
        return;
    }

    printf("%4ldKb\n", l);
}

/* STUB: Requires afp_sl_statfs() - not yet implemented */
int com_statvfs(char * arg)
{
    (void)arg; /* unused */
    printf("df/statvfs command not yet implemented via stateless library\n");
    printf("(requires afp_sl_statfs)\n");
    return -1;
}


int com_lcd(char * path)
{
    int ret;
    char curpath[PATH_MAX];
    ret = chdir(path);

    if (ret != 0) {
        perror("Changing directories");
    } else {
        getcwd(curpath, PATH_MAX);
        printf("Now in local directory %s\n", curpath);
    }

    return ret;
}

/* Change to the directory ARG. */
/* STUB: cd command needs refactoring - not yet fully implemented */
int com_cd(char *arg)
{
    (void)arg; /* unused */
    printf("cd command not yet fully implemented via stateless library\n");
    printf("Use 'connect afp://server/volume' to attach to a volume\n");
    printf("(needs refactoring for stateless mode)\n");
    return -1;
}

/* STUB: Exit command - simplified for stateless */
int com_exit(__attribute__((unused)) char *arg)
{
    if (connected) {
        return com_disconnect(NULL);
    }
    return 0;
}

/* Print out the current working directory locally. */
int com_lpwd(__attribute__((unused)) char * ignore)
{
    char dir[255];
    getcwd(dir, 255);
    printf("Now in local directory %s\n", dir);
    return 0;
}

/* Print out the current working directory. */
/* STUB: pwd command simplified for stateless */
int com_pwd(__attribute__((unused)) char * ignore)
{
    if (!connected) {
        printf("You're not connected to a volume yet\n");
        return -1;
    }
    printf("Now in directory %s\n", curdir);
    return 0;
}

/* STUB: get_dir needs refactoring for stateless library */
static int get_dir(char * server_base, char * path, unsigned long long *amount_written)
{
    (void)server_base; (void)path; (void)amount_written; /* unused */
    printf("Recursive directory get not yet implemented via stateless library\n");
    return -1;
}


/* STUB: Recursive get needs refactoring */
static int recursive_get(char * path)
{
    (void)path; /* unused */
    printf("Recursive get not yet fully implemented via stateless library\n");
    return -1;
}

static int cmdline_log_min_rank = 2; /* Default: LOG_NOTICE */

void cmdline_set_log_level(int loglevel)
{
    cmdline_log_min_rank = loglevel_to_rank(loglevel);
}

static void cmdline_log_for_client(__attribute__((unused)) void * priv,
                                   __attribute__((unused)) enum logtypes logtype,
                                   int loglevel, const char *message)
{
    int type_rank = loglevel_to_rank(loglevel);

    if (type_rank < cmdline_log_min_rank) {
        return; /* Filter out less-verbose messages */
    }

    /* Log to syslog - priv is always NULL for cmdline */
    syslog(loglevel, "%s", message);
}

static struct libafpclient afpclient = {
    .unmount_volume = NULL,
    .log_for_client = cmdline_log_for_client,
    .forced_ending_hook = cmdline_forced_ending_hook,
    .scan_extra_fds = NULL,
    .loop_started = cmdline_loop_started,
};

static void *cmdline_server_startup(int recursive)
{
    char mesg[MAX_ERROR_LEN];
    int error = 0;
    unsigned int uam_mask;
    serverid_t server_id;

    (void)recursive; /* Not used in stateless library yet */

    /* Determine UAM mask */
    if (strlen(url.uamname) > 0) {
        if ((uam_mask = find_uam_by_name(url.uamname)) == 0) {
            printf("I don't know about UAM %s\n", url.uamname);
            return (void *) -1;
        }
    } else {
        uam_mask = default_uams_mask();
    }

    /* Connect to server via stateless library */
    if (afp_sl_connect(&url, uam_mask, &server_id, mesg, &error)) {
        printf("Could not connect to server: %s\n", mesg);
        return (void *) -1;
    }

    printf("Connected to server %s\n", url.servername);

    /* Attach to volume if specified */
    if (strlen(url.volumename) > 0) {
        unsigned int volume_options = VOLUME_EXTRA_FLAGS_NO_LOCKING;

        if (afp_sl_attach(&url, volume_options, &vol_id)) {
            printf("Could not attach to volume %s\n", url.volumename);
            return (void *) -1;
        }

        printf("Attached to volume %s\n", url.volumename);
        connected = 1;

        /* Set working directory to URL path or default */
        if (strlen(url.path) > 0) {
            snprintf(curdir, AFP_MAX_PATH, "%s", url.path);
        } else {
            snprintf(curdir, AFP_MAX_PATH, "/");
        }
    }

    return NULL;
}

/* STUB: Needs stateless library cleanup */
void cmdline_afp_exit(void)
{
    if (connected) {
        afp_sl_detach(&vol_id, NULL);
        connected = 0;
    }
}

void cmdline_afp_setup_client(void)
{
    openlog("afpcmd", LOG_PID | LOG_CONS, LOG_USER);
    libafpclient_register(&afpclient);
}


int cmdline_afp_setup(int recursive, char * url_string)
{
    struct passwd * passwd;
    snprintf(curdir, AFP_MAX_PATH, "%s", DEFAULT_DIRECTORY);

    if (init_uams() < 0) {
        return -1;
    }

    afp_default_url(&url);
    passwd = getpwuid(getuid());
    strlcpy(url.username, passwd->pw_name, AFP_MAX_USERNAME_LEN);

    if ((url_string) && (strlen(url_string) > 1)) {
        if (afp_parse_url(&url, url_string, 0)) {
            printf("Could not parse url.\n");
        }

        cmdline_getpass();
        trigger_connected();
        cmdline_server_startup(recursive);
    }

    return 0;
}

