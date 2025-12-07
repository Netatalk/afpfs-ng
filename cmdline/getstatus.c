/*
 *
 *  Copyright (C) 2008 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "afp.h"
#include "afp_protocol.h"

#define FLAG_COUNT 16

bool show_icon = false;

const char *flag_descriptions[FLAG_COUNT] = {
    "SupportsCopyFile",
    "SupportsChgPwd",
    "DontAllowSavePwd",
    "SupportsServerMessages",
    "SupportsServerSignature",
    "SupportsTCP/IP",
    "SupportsSrvrNotifications",
    "SupportsReconnect",
    "SupportsOpenDirectory",
    "SupportsUTF8Servername",
    "SupportsUUIDs",
    "SupportsExtSleep",
    "Undocumented Bit12 (Supports GSS-UAM SPNEGO blob)",
    "Undocumented Bit13",
    "Undocumented Bit14",
    "SupportsSuperClient"
};

char **parse_afp_flags(uint16_t flags, int *count)
{
    char **flags_list = malloc(FLAG_COUNT * sizeof(char *));

    if (!flags_list) {
        return NULL;
    }

    int flag_index = 0;

    for (int i = 0; i < FLAG_COUNT; i++) {
        if (flags & (1 << i)) {
            flags_list[flag_index] = malloc(50);

            if (!flags_list[flag_index]) {
                for (int j = 0; j < flag_index; j++) {
                    free(flags_list[j]);
                }

                free(flags_list);
                return NULL;
            }

            snprintf(flags_list[flag_index], 50, "\t%s", flag_descriptions[i]);
            flag_index++;
        }
    }

    *count = flag_index;
    return flags_list;
}

void draw_icon(int offset, char icon[])
{
    int cols = 0;
    int i, j;

    // icons are 32x32 bitmaps; 128-byte icon + 128-byte mask
    for (i = 0; i < AFP_SERVER_ICON_LEN; i++) {
        char c = icon[i + offset];

        for (j = 7; j >= 0; j--) {
            if (c & (1 << j)) {
                printf("#");
            } else {
                printf(" ");
            }
        }

        cols++;

        if (cols == 4) {
            cols = 0;
            printf("\n");
        }
    }

    printf("\n");
}

static int getstatus(char *address_string, unsigned int port)
{
    struct afp_server *server;
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *p;
    int ret;
    struct afp_versions *tmpversion;
    char ipstr[INET6_ADDRSTRLEN];
    char port_str[6];
    int count;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", port);

    if ((ret = getaddrinfo(address_string, port_str, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    printf("AFP response from %s:%d via ", address_string, port);

    if (res->ai_family == AF_INET) {
        printf("IPv4\n");
    } else if (res->ai_family == AF_INET6) {
        printf("IPv6\n");
    } else {
        printf("unknown address family\n");
    }

    server = afp_server_init(res);
    ret = afp_server_connect(server, 1);

    if (ret < 0) {
        perror("Connecting to server");
        freeaddrinfo(res);
        return -1;
    }

    char **flags = parse_afp_flags(server->flags, &count);
    printf("Server name: %s\n", server->server_name_printable);
    printf("Server type: %s\n", server->machine_type);
    printf("AFP versions:\n");

    for (int j = 0; j < SERVER_MAX_VERSIONS; j++) {
        for (tmpversion = afp_versions; tmpversion->av_name; tmpversion++) {
            if (tmpversion->av_number == server->versions[j]) {
                printf("\t%s\n", tmpversion->av_name);
                break;
            }
        }
    }

    printf("UAMs:\n");

    for (int j = 1; j < 0x100; j <<= 1) {
        if (j & server->supported_uams) {
            printf("\t%s\n", uam_bitmap_to_string(j));
        }
    }

    printf("Flags:\n");

    if (flags) {
        for (int i = 0; i < count; i++) {
            printf("%s\n", flags[i]);
            free(flags[i]);
        }

        free(flags);
    }

    printf("Signature:\n\t");

    for (int j = 0; j < AFP_SIGNATURE_LEN; j++) {
        printf("%02x ", (unsigned char)server->signature[j]);
    }

    printf("\n\t");

    for (int j = 0; j < AFP_SIGNATURE_LEN; j++) {
        unsigned char c = (unsigned char)server->signature[j];

        if (c >= 32 && c <= 126) {
            printf("%c", c);
        } else {
            printf(".");
        }
    }

    printf("\n");

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        char *ipver;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("Resolved %s address: %s\n", ipver, ipstr);
    }

    if (show_icon) {
        draw_icon(0, server->icon);
    }

    freeaddrinfo(res);
    free(server);
    return 0;
}

static void usage(void)
{
    printf("afpfs-ng %s - get Apple Filing Protocol server status\n"
           "Usage:\n"
           "\tgetstatus [afp_url|ipaddress[:port]] [-i]\n", AFPFS_VERSION);
}

int main(int argc, char *argv[])
{
    unsigned int port = 548;
    struct afp_url url;
    char *servername = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            show_icon = true;
        } else if (servername == NULL) {
            servername = argv[i];
        } else {
            usage();
            return -1;
        }
    }

    if (servername == NULL) {
        usage();
        return -1;
    }

    afp_default_url(&url);

    if (afp_parse_url(&url, servername, 0) != 0) {
        char *p;
        struct in6_addr ipv6_addr;
        struct in_addr ipv4_addr;

        /* Check if it's an IPv6 address with brackets and port */
        if (servername[0] == '[') {
            char *closing_bracket = strchr(servername, ']');

            if (closing_bracket) {
                *closing_bracket = '\0';
                servername++; // Skip the opening bracket
                p = closing_bracket + 1; // Move to the port part

                if (*p == ':') {
                    p++;

                    if ((port = atoi(p)) <= 0) {
                        printf("Could not understand port %s\n", p);
                        usage();
                        return -1;
                    }
                }
            } else {
                printf("Invalid IPv6 address format: missing closing bracket\n");
                usage();
                return -1;
            }
        }
        /* Check if it's an IPv6 address without brackets */
        else if (inet_pton(AF_INET6, servername, &ipv6_addr) == 1) {
            /* It's a valid IPv6 address without brackets */
            /* No need to extract a port */
        }
        /* Check if it's an IPv4 address with port */
        else if ((p = strchr(servername, ':')) != NULL) {
            *p = '\0'; // Terminate the servername
            p++;

            if ((port = atoi(p)) <= 0) {
                printf("Could not understand port %s\n", p);
                usage();
                return -1;
            }
        }
        /* Check if it's an IPv4 address without port */
        else if (inet_pton(AF_INET, servername, &ipv4_addr) == 1) {
            /* It's a valid IPv4 address without port */
            /* No need to extract a port */
        }
        /* Assume it's a hostname without port */
        else {
            /* No need to extract a port */
        }
    } else {
        servername = url.servername;
        port = url.port;
    }

    libafpclient_register(NULL);
    afp_main_quick_startup(NULL);

    if (getstatus(servername, port) == 0) {
        return 0;
    } else {
        return -1;
    }
}
