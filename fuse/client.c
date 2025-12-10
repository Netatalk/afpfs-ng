/*
 *  client.c
 *
 *  Copyright (C) 2007 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <limits.h>

#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LIBBSD
#include <bsd/string.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "afp.h"
#include "afp_server.h"
#include "uams_def.h"
#include "map_def.h"
#include "libafpclient.h"

#define default_uam "Cleartxt Passwrd"

#define MAX_OUTGOING_LENGTH 8192

#define AFPFSD_FILENAME "afpfsd"
#define DEFAULT_MOUNT_FLAGS (VOLUME_EXTRA_FLAGS_SHOW_APPLEDOUBLE|\
	VOLUME_EXTRA_FLAGS_NO_LOCKING | VOLUME_EXTRA_FLAGS_IGNORE_UNIXPRIVS)

static char outgoing_buffer[MAX_OUTGOING_LENGTH];
static int outgoing_len = 0;
static unsigned int uid, gid = 0;
static int changeuid = 0;
static int changegid = 0;
static char *thisbin;

/* Forward declaration for get_daemon_filename */
static void get_daemon_filename(char *filename, size_t size,
                                const char *mountpoint);

/* SIGCHLD handler to reap child processes and prevent zombies */
static void sigchld_handler(int sig)
{
    (void)sig;  /* Unused parameter */
    int status;

    /* Reap all available child processes */
    while (waitpid(-1, &status, WNOHANG) > 0) {
        /* Child has been reaped */
    }
}

static int start_manager_daemon(void)
{
    char *argv[4];
    int argc = 0;
    struct sigaction sa, old_sa;
    argv[argc++] = AFPFSD_FILENAME;
    argv[argc++] = "--manager";
    argv[argc] = NULL;
    /* Temporarily install SIGCHLD handler to reap any child process failures */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, &old_sa);

    if (fork() == 0) {
        char filename[PATH_MAX];

        if (changegid) {
            if (setegid(gid)) {
                perror("Changing gid");
                _exit(1);
            }
        }

        if (changeuid) {
            if (seteuid(uid)) {
                perror("Changing uid");
                _exit(1);
            }
        }

        snprintf(filename, PATH_MAX, AFPFSD_FILENAME);

        if (getenv("PATH") == NULL) {
            /* If we don't have an PATH set, it is probably
               becaue we are being called from mount,
               so go search for it */
            snprintf(filename, PATH_MAX,
                     "/usr/local/bin/%s", AFPFSD_FILENAME);

            if (access(filename, X_OK)) {
                snprintf(filename, sizeof(filename), "/usr/bin/%s",
                         AFPFSD_FILENAME);
                filename[sizeof(filename) - 1] = 0;

                if (access(filename, X_OK)) {
                    fprintf(stderr, "Could not find server (%s)\n",
                            filename);
                    _exit(1);
                }
            }
        }

        if (execvp(filename, argv)) {
            if (errno == ENOENT) {
                /* Try the path of afp_client */
                char newpath[PATH_MAX];
                snprintf(newpath, PATH_MAX, "%s/%s",
                         (char *)basename(thisbin), AFPFSD_FILENAME);

                if (execvp(newpath, argv)) {
                    perror("Starting up afpfsd manager");
                    _exit(1);
                }
            } else {
                perror("Starting up afpfsd manager");
                _exit(1);
            }
        }

        /* execvp never returns on success */
        _exit(1);
    }

    /* Restore old signal handler */
    sigaction(SIGCHLD, &old_sa, NULL);
    return 0;
}

static int start_afpfsd(const char *mountpoint)
{
    int sock;
    struct sockaddr_un servaddr;
    char manager_socket[PATH_MAX];
    char mount_socket[PATH_MAX];
    struct afp_server_spawn_mount_request req;
    unsigned char command = AFP_SERVER_COMMAND_SPAWN_MOUNT;
    unsigned char result;
    /* Get manager socket name (NULL = shared socket) */
    get_daemon_filename(manager_socket, sizeof(manager_socket), NULL);
    /* Get mount-specific socket name */
    get_daemon_filename(mount_socket, sizeof(mount_socket), mountpoint);

    /* Try to connect to manager daemon */
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;

    if (strlcpy(servaddr.sun_path, manager_socket,
                sizeof(servaddr.sun_path)) >= sizeof(servaddr.sun_path)) {
        close(sock);
        fprintf(stderr, "Manager socket path too long\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&servaddr,
                sizeof(servaddr.sun_family) + sizeof(servaddr.sun_path)) < 0) {
        /* Manager not running, start it */
        close(sock);

        if (start_manager_daemon() != 0) {
            return -1;
        }

        /* Wait for manager to start */
        sleep(1);

        /* Reconnect to manager */
        if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            return -1;
        }

        if (connect(sock, (struct sockaddr *)&servaddr,
                    sizeof(servaddr.sun_family) + sizeof(servaddr.sun_path)) < 0) {
            close(sock);
            perror("Could not connect to manager daemon");
            return -1;
        }
    }

    /* Send spawn mount request */
    memset(&req, 0, sizeof(req));
    snprintf(req.mountpoint, sizeof(req.mountpoint), "%s", mountpoint);
    snprintf(req.socket_id, sizeof(req.socket_id), "%s", mount_socket);

    if (write(sock, &command, 1) != 1) {
        close(sock);
        return -1;
    }

    if (write(sock, &req, sizeof(req)) != sizeof(req)) {
        close(sock);
        return -1;
    }

    /* Wait for response */
    if (read(sock, &result, 1) != 1) {
        close(sock);
        return -1;
    }

    close(sock);

    if (result != AFP_SERVER_RESULT_OKAY) {
        return -1;
    }

    return 0;
}


/* Each mount gets a unique daemon process for fault isolation.
 * Management commands use NULL mountpoint to get shared management socket. */
static void get_daemon_filename(char *filename, size_t size,
                                const char *mountpoint)
{
    unsigned long hash = 5381;

    if (mountpoint) {
        /* Hash the mountpoint path to create unique socket per mount */
        for (const char *p = mountpoint; *p; p++) {
            hash = ((hash << 5) + hash) ^ (unsigned char) * p;
        }

        /* One daemon per mountpoint */
        snprintf(filename, size, "%s-%d-%lx", SERVER_FILENAME, uid, hash);
    } else {
        /* Shared management socket for status/exit commands */
        snprintf(filename, size, "%s-%d", SERVER_FILENAME, uid);
    }
}

static int daemon_connect(const char *mountpoint)
{
    int sock;
    struct sockaddr_un servaddr;
    char filename[PATH_MAX];
    unsigned char trying = 2;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("Could not create socket\n");
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    get_daemon_filename(filename, sizeof(filename), mountpoint);

    if (strlcpy(servaddr.sun_path, filename,
                sizeof(servaddr.sun_path)) >= sizeof(servaddr.sun_path)) {
        close(sock);
        fprintf(stderr, "Socket path too long\n");
        return -1;
    }

    while (trying) {
        if ((connect(sock, (struct sockaddr *) &servaddr,
                     sizeof(servaddr.sun_family) +
                     sizeof(servaddr.sun_path))) >= 0) {
            goto done;
        }

        if (start_afpfsd(mountpoint) != 0) {
            perror("Error in starting up afpfsd\n");
            goto error;
        }

        if ((connect(sock, (struct sockaddr *) &servaddr,
                     sizeof(servaddr.sun_family) +
                     sizeof(servaddr.sun_path))) >= 0) {
            goto done;
        }

        sleep(1);
        trying--;
    }

error:
    perror("Trying to startup afpfsd");
    return -1;
done:
    return sock;
}


static void usage(void)
{
    printf(
        "afp_client [command] [options]\n"
        "    mount [mountopts] <server>:<volume> <mountpoint>\n"
        "         mount options:\n"
        "         -u, --user <username> : log in as user <username>\n"
        "         -p, --pass <password> : use <password>\n"
        "                           If password is '-', password will be hidden\n"
        "         -o, --port <portnum> : connect using <portnum> instead of 548\n"
        "         -V, --volumepassword <volpass> : use this volume password\n"
        "         -v, --afpversion <afpversion> set the AFP version, eg. 3.1\n"
        "         -a, --uam <uam> : use this authentication method, one of:\n"
        "               \"No User Authent\", \"Cleartxt Passwrd\", \n"
        "               \"Randnum Exchange\", \"2-Way Randnum Exchange\", \n"
        "               \"DHCAST128\", \"Client Krb v2\", \"DHX2\" \n\n"
        "         -m, --map <mapname> : use this uid/gid mapping method, one of:\n"
        "               \"Common user directory\", \"Login ids\"\n"
        "         -O, --options <flags> : FUSE mount options, see man mount.fuse\n"
        "    status: get status of the AFP daemon\n\n"
        "    unmount <mountpoint> : unmount\n\n"
        "    suspend <servername> : terminates the connection to the server, but\n"
        "                           maintains the mount.  For laptop suspend/resume\n"
        "    resume  <servername> : resumes the server connection \n\n"
        "    exit                 : unmounts all volumes and exits afpfsd\n"
    );
}


static char *get_password(const char *prompt)
{
    if (isatty(fileno(stdin))) {
        return getpass(prompt);
    } else {
        char *askpass = NULL;
        static char pwd[AFP_MAX_PASSWORD_LEN + 1];
        FILE *fp;
        asprintf(&askpass, "ssh-askpass %s", prompt);

        if ((fp = popen(askpass, "r"))) {
            fread(pwd, 1, sizeof(pwd), fp);
            pclose(fp);
            // ssh-askpass always adds a newline: chop it.
            pwd[strlen(pwd) - 1] = '\0';
        } else {
            perror(askpass);
            memset(pwd, (int) sizeof(pwd), (0));
        }

        return pwd;
    }
}

static int send_command(int sock, char * msg, int len)
{
    return write(sock, msg, len);
}

static int do_exit(__attribute__((unused)) int argc,
                   __attribute__((unused)) char **argv)
{
    outgoing_len = 1;
    outgoing_buffer[0] = AFP_SERVER_COMMAND_EXIT;
    return 0;
}

/* Resolve mountpoint to absolute path */
static int resolve_mountpoint(const char *path, char *resolved, size_t size)
{
    char *result;

    /* If already absolute, just copy it */
    if (path[0] == '/') {
        snprintf(resolved, size, "%s", path);
        return 0;
    }

    /* Resolve relative path */
    result = realpath(path, NULL);

    if (result) {
        snprintf(resolved, size, "%s", result);
        free(result);
        return 0;
    }

    /* realpath failed - path might not exist yet, build absolute path manually */
    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("getcwd");
        return -1;
    }

    /* Check if combined path fits in buffer */
    size_t needed = strlen(cwd) + 1 + strlen(path) + 1;

    if (needed > size) {
        fprintf(stderr, "Mountpoint path too long\n");
        return -1;
    }

    int ret = snprintf(resolved, size, "%s/%s", cwd, path);

    if (ret < 0 || (size_t)ret >= size) {
        fprintf(stderr, "Mountpoint path formatting error\n");
        return -1;
    }

    return 0;
}

static int do_status(int argc, char ** argv)
{
    int c;
    int option_index = 0;
    struct afp_server_status_request req = {0};
    struct option long_options[] = {
        {"volume", 1, 0, 'v'},
        {"server", 1, 0, 's'},
        {0, 0, 0, 0},
    };
    outgoing_buffer[0] = AFP_SERVER_COMMAND_STATUS;
    outgoing_len = sizeof(struct afp_server_status_request) + 1;

    while (1) {
        c = getopt_long(argc, argv, "v:s:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'v':
            snprintf(req.volumename, AFP_VOLUME_NAME_LEN, "%s", optarg);
            break;
        }
    }

    memcpy(outgoing_buffer + 1, &req, sizeof(req));
    return 0;
}

static int do_resume(int argc, char ** argv)
{
    struct afp_server_resume_request request = {0};

    if (argc < 3) {
        usage();
        return -1;
    }

    outgoing_buffer[0] = AFP_SERVER_COMMAND_RESUME;
    outgoing_len = sizeof(struct afp_server_resume_request) + 1;
    snprintf(request.server_name, AFP_SERVER_NAME_LEN, "%s", argv[2]);
    memcpy(outgoing_buffer + 1, &request, sizeof(request));
    return 0;
}

static int do_suspend(int argc, char ** argv)
{
    struct afp_server_suspend_request request = {0};

    if (argc < 3) {
        usage();
        return -1;
    }

    outgoing_buffer[0] = AFP_SERVER_COMMAND_SUSPEND;
    outgoing_len = sizeof(struct afp_server_suspend_request) + 1;
    snprintf(request.server_name, AFP_SERVER_NAME_LEN, "%s", argv[2]);
    memcpy(outgoing_buffer + 1, &request, sizeof(request));
    return 0;
}

static int do_unmount(int argc, char ** argv)
{
    struct afp_server_unmount_request request = {0};

    if (argc < 2) {
        usage();
        return -1;
    }

    outgoing_buffer[0] = AFP_SERVER_COMMAND_UNMOUNT;
    outgoing_len = sizeof(struct afp_server_unmount_request) + 1;
    snprintf(request.mountpoint, 255, "%s", argv[2]);
    memcpy(outgoing_buffer + 1, &request, sizeof(request));
    return 0;
}

static int do_mount(int argc, char ** argv)
{
    int c;
    int option_index = 0;
    struct afp_server_mount_request request = {0};
    int optnum = 0;
    unsigned int uam_mask = default_uams_mask();
    struct option long_options[] = {
        {"afpversion", 1, 0, 'v'},
        {"volumepassword", 1, 0, 'V'},
        {"user", 1, 0, 'u'},
        {"pass", 1, 0, 'p'},
        {"port", 1, 0, 'o'},
        {"uam", 1, 0, 'a'},
        {"map", 1, 0, 'm'},
        {"options", 1, 0, 'O'},
        {0, 0, 0, 0},
    };

    if (argc < 4) {
        usage();
        return -1;
    }

    outgoing_buffer[0] = AFP_SERVER_COMMAND_MOUNT;
    outgoing_len = sizeof(struct afp_server_mount_request) + 1;
    request.url.port = 548;
    request.map = AFP_MAPPING_UNKNOWN;
    request.fuse_options[0] = '\0';

    while (1) {
        optnum++;
        c = getopt_long(argc, argv, "a:u:m:o:p:v:V:O:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'a':
            if (strcmp(optarg, "guest") == 0) {
                uam_mask = UAM_NOUSERAUTHENT;
            } else {
                uam_mask = uam_string_to_bitmap(optarg);
            }

            break;

        case 'm':
            request.map = map_string_to_num(optarg);
            break;

        case 'u':
            snprintf(request.url.username, AFP_MAX_USERNAME_LEN, "%s", optarg);
            break;

        case 'o':
            request.url.port = strtol(optarg, NULL, 10);
            break;

        case 'p':
            snprintf(request.url.password, AFP_MAX_PASSWORD_LEN, "%s", optarg);
            break;

        case 'V':
            snprintf(request.url.volpassword, 9, "%s", optarg);
            break;

        case 'v':
            request.url.requested_version = strtol(optarg, NULL, 10);
            break;

        case 'O':
            snprintf(request.fuse_options, sizeof(request.fuse_options), "%s", optarg);
            break;
        }
    }

    // Handle password prompts
    if (strcmp(request.url.password, "-") == 0) {
        char *p = get_password("AFP Password: ");

        if (p) {
            snprintf(request.url.password, AFP_MAX_PASSWORD_LEN, "%s", p);
        }
    }

    if (strcmp(request.url.volpassword, "-") == 0) {
        char *p = get_password("Password for volume: ");

        if (p) {
            snprintf(request.url.volpassword, 9, "%s", p);
        }
    }

    optnum = optind + 1;

    if (optnum >= argc) {
        printf("No volume or mount point specified\n");
        return -1;
    }

    if (sscanf(argv[optnum++], "%[^':']:%[^':']",
               request.url.servername, request.url.volumename) != 2) {
        printf("Incorrect server:volume specification\n");
        return -1;
    }

    if (uam_mask == 0) {
        printf("Unknown UAM\n");
        return -1;
    }

    request.uam_mask = uam_mask;
    request.volume_options = DEFAULT_MOUNT_FLAGS;

    if (optnum >= argc) {
        printf("No mount point specified\n");
        return -1;
    }

    if (resolve_mountpoint(argv[optnum], request.mountpoint, 255) < 0) {
        printf("Failed to resolve mount point\n");
        return -1;
    }

    memcpy(outgoing_buffer + 1, &request, sizeof(request));
    return 0;
}

static void mount_afp_usage(void)
{
    printf("afpfs-ng %s - mount an Apple Filing Protocol network filesystem with FUSE\n"
           "Usage:\n"
           "\tmount_afpfs [-o volpass=password] <afp url> <mountpoint>\n", AFPFS_VERSION);
}

static int handle_mount_afp(int argc, char * argv[])
{
    struct afp_server_mount_request * req = (struct afp_server_mount_request *)
                                            &outgoing_buffer[1];
    unsigned int uam_mask = default_uams_mask();
    char *urlstring, *mountpoint;
    char *volpass = NULL;
    int readonly = 0;

    if (argc < 2) {
        mount_afp_usage();
        return -1;
    }

    if (strncmp(argv[1], "-o", 2) == 0) {
        char *p = argv[2], *q;
        char command[256];
        struct passwd * passwd;
        struct group * group;

        do {
            memset(command, 0, 256);

            if ((q = strchr(p, ','))) {
                strlcpy(command, p, (q - p));
            } else {
                strlcpy(command, p, sizeof(command));
            }

            if (strncmp(command, "volpass=", 8) == 0) {
                p += 8;
                volpass = p;
            } else if (strncmp(command, "user=", 5) == 0) {
                p = command + 5;

                if ((passwd = getpwnam(p)) == NULL) {
                    printf("Unknown user %s\n", p);
                    return -1;
                }

                uid = passwd->pw_uid;

                if (geteuid() != uid) {
                    changeuid = 1;
                }
            } else if (strncmp(command, "group=", 6) == 0) {
                p = command + 6;

                if ((group = getgrnam(p)) == NULL) {
                    printf("Unknown group %s\n", p);
                    return -1;
                }

                gid = group->gr_gid;
                changegid = 1;
            } else if (strcmp(command, "rw") == 0) {
                /* Don't do anything */
            } else if (strcmp(command, "ro") == 0) {
                readonly = 1;
            } else {
                printf("Unknown option %s, skipping\n", command);
            }

            if (q) {
                p = q + 1;
            } else {
                p = NULL;
            }
        } while (p);

        urlstring = argv[3];
        mountpoint = argv[4];
    } else {
        urlstring = argv[1];
        mountpoint = argv[2];
    }

    outgoing_len = sizeof(struct afp_server_mount_request) +1;
    memset(outgoing_buffer, 0, outgoing_len);
    afp_default_url(&req->url);
    req->changeuid = changeuid;
    req->volume_options |= DEFAULT_MOUNT_FLAGS;

    if (readonly) {
        req->volume_options |= VOLUME_EXTRA_FLAGS_READONLY;
    }

    req->uam_mask = uam_mask;
    outgoing_buffer[0] = AFP_SERVER_COMMAND_MOUNT;
    req->map = AFP_MAPPING_UNKNOWN;

    if (resolve_mountpoint(mountpoint, req->mountpoint, 255) < 0) {
        printf("Failed to resolve mount point\n");
        return -1;
    }

    if (afp_parse_url(&req->url, urlstring, 0) != 0) {
        printf("Could not parse URL\n");
        return -1;
    }

    if (strcmp(req->url.password, "-") == 0) {
        char *p = get_password("AFP Password: ");

        if (p) {
            snprintf(req->url.password, AFP_MAX_PASSWORD_LEN, "%s", p);
        }
    }

    if (volpass && (strcmp(volpass, "-") == 0)) {
        volpass  = get_password("Password for volume: ");
    }

    if (volpass) {
        snprintf(req->url.volpassword, 9, "%s", volpass);
    }

    return 0;
}

static int prepare_buffer(int argc, char * argv[])
{
    if (argc < 2) {
        usage();
        return -1;
    }

    if (strncmp(argv[1], "mount", 5) == 0) {
        return do_mount(argc, argv);
    } else if (strncmp(argv[1], "resume", 6) == 0) {
        return do_resume(argc, argv);
    } else if (strncmp(argv[1], "suspend", 7) == 0) {
        return do_suspend(argc, argv);
    } else if (strncmp(argv[1], "status", 6) == 0) {
        return do_status(argc, argv);
    } else if (strncmp(argv[1], "unmount", 7) == 0) {
        return do_unmount(argc, argv);
    } else if (strncmp(argv[1], "exit", 4) == 0) {
        return do_exit(argc, argv);
    } else {
        usage();
        return -1;
    }

    return 0;
}


int read_answer(int sock)
{
    int len = 0, expected_len = 0, packetlen;
    char incoming_buffer[MAX_CLIENT_RESPONSE];
    struct timeval tv;
    fd_set rds, ords;
    int ret;
    struct afp_server_response * answer = (void *) incoming_buffer;
    memset(incoming_buffer, 0, MAX_CLIENT_RESPONSE);
    FD_ZERO(&rds);
    FD_SET(sock, &rds);

    while (1) {
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        ords = rds;
        ret = select(sock + 1, &ords, NULL, NULL, &tv);

        if (ret == 0) {
            printf("No response from server\n");
            return -1;
        }

        if (FD_ISSET(sock, &ords)) {
            packetlen = read(sock, incoming_buffer + len, MAX_CLIENT_RESPONSE - len);

            if (packetlen == 0) {
                printf("Connection closed\n");
                goto done;
            }

            if (len == 0) {
                expected_len = ((struct afp_server_response *) incoming_buffer)->len;
            }

            len += packetlen;

            if ((unsigned long) len == expected_len + sizeof(struct afp_server_response)) {
                goto done;
            }

            if (ret < 0) {
                goto error;
            }
        }
    }

done:
    printf("%.200s", incoming_buffer + sizeof(*answer));
    return ((struct afp_server_response *) incoming_buffer)->result;
    return 0;
error:
    return -1;
}

int main(int argc, char *argv[])
{
    int sock;
    int ret;
    const char *mountpoint = NULL;
#if 0
    struct afp_volume volume;
#endif
    thisbin = argv[0];
    uid = ((unsigned int) geteuid());
#if 0
    volume.server = NULL;
#endif

    if (strstr(argv[0], "mount_afp")) {
        if (handle_mount_afp(argc, argv) < 0) {
            return -1;
        }

        /* Extract mountpoint from mount request for per-mount daemon routing */
        if (outgoing_buffer[0] == AFP_SERVER_COMMAND_MOUNT && outgoing_len > 1) {
            const struct afp_server_mount_request *req =
                (const struct afp_server_mount_request *)(outgoing_buffer + 1);
            mountpoint = req->mountpoint;
        }
    } else if (prepare_buffer(argc, argv) < 0) {
        return -1;
    }

    /* Extract mountpoint for per-mount daemon routing */
    if (mountpoint == NULL) {
        if (outgoing_buffer[0] == AFP_SERVER_COMMAND_MOUNT && outgoing_len > 1) {
            const struct afp_server_mount_request *req =
                (const struct afp_server_mount_request *)(outgoing_buffer + 1);
            mountpoint = req->mountpoint;
        } else if (outgoing_buffer[0] == AFP_SERVER_COMMAND_UNMOUNT
                   && outgoing_len > 1) {
            const struct afp_server_unmount_request *req =
                (const struct afp_server_unmount_request *)(outgoing_buffer + 1);
            mountpoint = req->mountpoint;
        }
    }

    if ((sock = daemon_connect(mountpoint)) < 0) {
        return -1;
    }

    send_command(sock, outgoing_buffer, outgoing_len);
    ret = read_answer(sock);
    return ret;
}

