/*
	Copyright (C) 2008 Alex deVries

*/

#include "afp.h"
#include "midlevel.h"

#include "cmdline_main.h"

#include <stdlib.h>
#include <stdio.h>

extern struct afp_volume *vol;

static int test_one_url(char * url_string,
                        e_proto protocol,
                        char *username,
                        char *uamname,
                        char *password,
                        char *servername,
                        int port,
                        char *volumename,
                        char *path)
{
    struct afp_url valid_url;
    afp_default_url(&valid_url);
    valid_url.protocol = protocol;
    snprintf(valid_url.servername, sizeof(valid_url.servername), "%s", servername);
    snprintf(valid_url.volumename, sizeof(valid_url.volumename), "%s", volumename);
    snprintf(valid_url.path, sizeof(valid_url.path), "%s", path);
    snprintf(valid_url.username, sizeof(valid_url.username), "%s", username);
    snprintf(valid_url.password, sizeof(valid_url.password), "%s", password);
    snprintf(valid_url.uamname, sizeof(valid_url.uamname), "%s", uamname);
    valid_url.port = port;

    if (afp_url_validate(url_string, &valid_url)) {
        printf("* Could not parse %s\n", url_string);
    } else {
        printf("* Parsed %s correctly\n", url_string);
    }

    return 0;
}

int test_urls(__attribute__((unused)) char *arg)
{
    printf("Testing AFP URL parsing\n");
    test_one_url("afp://user::name;AUTH=DHCAST128:pa@@sword@server/volume/path",
                 TCPIP, "user:name", "DHCAST128", "pa@sword", "server", 548, "volume", "path");
    test_one_url("afp://username;AUTH=DHCAST128:password@server/volume/path",
                 TCPIP, "username", "DHCAST128", "password", "server", 548, "volume", "path");
    test_one_url("afp://username;AUTH=DHCAST128:password@server:548/volume/path",
                 TCPIP, "username", "DHCAST128", "password", "server", 548, "volume", "path");
    test_one_url("afp://username:password@server/volume/path",
                 TCPIP, "username", "", "password", "server", 548, "volume", "path");
    test_one_url("afp://username@server/volume/path",
                 TCPIP, "username", "", "", "server", 548, "volume", "path");
    test_one_url("afp://server/volume/path",
                 TCPIP, "", "", "", "server", 548, "volume", "path");
    test_one_url("afp://server/",
                 TCPIP, "", "", "", "server", 548, "", "");
    test_one_url("afp://server:22/",
                 TCPIP, "", "", "", "server", 22, "", "");
    test_one_url("afp://server:22",
                 TCPIP, "", "", "", "server", 22, "", "");
    test_one_url("afp://server:22/volume/",
                 TCPIP, "", "", "", "server", 22, "volume", "");
    return 0;
}
