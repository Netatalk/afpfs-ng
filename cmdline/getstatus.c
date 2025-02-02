#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "afp.h"

static int getstatus(char *address_string, unsigned int port)
{
	struct afp_server *server;
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *p;
	int ret;
	char signature_string[AFP_SIGNATURE_LEN * 2 + 1];
	struct afp_versions *tmpversion;
	char host[NI_MAXHOST];
	char ipstr[INET6_ADDRSTRLEN];
	char port_str[6];

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

	printf("Server name: %s\n", server->server_name_printable);
	printf("Server type: %s\n", server->machine_type);
	printf("AFP versions: \n");

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

	freeaddrinfo(res);
	free(server);
	return 0;
}

static void usage(void)
{
	printf("getstatus [afp_url|ipaddress[:port]]\n");
}

int main(int argc, char *argv[])
{
	unsigned int port = 548;
	struct afp_url url;
	char *servername = argv[1];
	pthread_t loop_thread;

	if (argc != 2) {
		usage();
		return -1;
	}

	afp_default_url(&url);

	if (afp_parse_url(&url, argv[1], 0) != 0) {
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
