/*
 *  uams.c
 *
 *  Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2007 Derrik Pates <dpates@dsdk12.net>
 *  Copyright (C) 2025-2026 Daniel Markstedt <daniel@mindani.net>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#include <assert.h>
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBBSD
#include <bsd/string.h>
#endif

#include "compat.h"
#include "dsi.h"
#include "afp.h"
#include "utils.h"
#include "uams_def.h"
#include "uams.h"

struct afp_uam {
    unsigned int bitmap;
    char name[AFP_UAM_LENGTH];
    int (*do_server_login)(struct afp_server *server, char *username,
                           char *password);
    int (*do_server_passwd)(struct afp_server * server, char *username,
                            char *oldpasswd, char *newpasswd);
    struct afp_uam *next;
};

static struct afp_uam *uam_base = NULL;

static int noauth_login(struct afp_server *server, char *username,
                        char *passwd);

static struct afp_uam uam_noauth =
{UAM_NOUSERAUTHENT, "No User Authent", &noauth_login, NULL, NULL};
static struct afp_uam uam_cleartxt = {
    UAM_CLEARTXTPASSWRD, "Cleartxt Passwrd", &cleartxt_login,
    &cleartxt_passwd, NULL
};
#ifdef HAVE_LIBGCRYPT
static struct afp_uam uam_randnum =
{UAM_RANDNUMEXCHANGE, "Randnum Exchange", &randnum_login, &randnum_passwd, NULL};
static struct afp_uam uam_randnum2 =
{UAM_2WAYRANDNUM, "2-Way Randnum Exchange", &randnum2_login, &randnum_passwd, NULL};
static struct afp_uam uam_dhx =
{UAM_DHCAST128, "DHCAST128", &dhx_login, &dhx_passwd, NULL};
static struct afp_uam uam_dhx2 =
{UAM_DHX2, "DHX2", &dhx2_login, &dhx2_passwd, NULL};

#endif /* HAVE_LIBGCRYPT */

#define UAMS_MAX_NAMES_LIST 255
char uam_names_list[UAMS_MAX_NAMES_LIST];

unsigned int default_uams_mask(void)
{
    unsigned int uam_mask = UAM_CLEARTXTPASSWRD ;
#ifdef HAVE_LIBGCRYPT
    uam_mask |= UAM_RANDNUMEXCHANGE | UAM_2WAYRANDNUM;
    uam_mask |= UAM_DHCAST128 | UAM_DHX2;
#endif
    return uam_mask;
}

char *get_uam_names_list(void)
{
    return uam_names_list;
}

static int register_uam(struct afp_uam * uam)
{
    struct afp_uam * u = uam_base;

    if ((uam->bitmap = uam_string_to_bitmap(uam->name)) == 0) {
        goto error;
    }

    if (!uam_base)  {
        uam_base = uam;
        u = uam;
    } else {
        for (; u->next; u = u->next);

        u->next = uam;
    }

    uam->next = NULL;
    /* Add the name to the larger list */
    {
        size_t cur_len = strlen(uam_names_list);
        size_t remaining = UAMS_MAX_NAMES_LIST - cur_len;
        int written;

        if (cur_len) {
            written = snprintf(uam_names_list + cur_len, remaining,
                               ", %s", uam->name);
        } else {
            written = snprintf(uam_names_list + cur_len, remaining,
                               "%s", uam->name);
        }

        if (written < 0 || (size_t)written >= remaining) {
            goto error;
        }
    }
    return 0;
error:
    log_for_client(NULL, AFPFSD, LOG_WARNING, "Could not register all UAMs");
    return -1;
}

static struct afp_uam *find_uam_by_bitmap(unsigned int i)
{
    struct afp_uam * u = uam_base;

    for (; u; u = u->next)
        if (u->bitmap == i) {
            return u;
        }

    return NULL;
}

unsigned int find_uam_by_name(const char * name)
{
    struct afp_uam * u = uam_base;
    const char *resolved_name = resolve_uam_shorthand(name);

    for (; u; u = u->next)
        if (strcmp(u->name, resolved_name) == 0) {
            return u->bitmap;
        }

    return 0;
}

int init_uams(void)
{
    memset(uam_names_list, 0, UAMS_MAX_NAMES_LIST);
    register_uam(&uam_cleartxt);
    register_uam(&uam_noauth);
#ifdef HAVE_LIBGCRYPT
    register_uam(&uam_randnum);
    register_uam(&uam_randnum2);
    register_uam(&uam_dhx);
    register_uam(&uam_dhx2);
#endif /* HAVE_LIBGCRYPT */
    return 0;
}

static int noauth_login(
    struct afp_server *server,
    __attribute__((unused)) char *username,
    __attribute__((unused)) char *passwd
)
{
    return afp_login(server, "No User Authent", NULL, 0, NULL);
}

int afp_dologin(struct afp_server *server,
                unsigned int uam, char *username, char *passwd)
{
    struct afp_uam * u;

    if ((u = find_uam_by_bitmap(uam)) == NULL) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "afp_dologin -- Unknown UAM");
        return -1;
    }

    return u->do_server_login(server, username, passwd);
}

int afp_dopasswd(struct afp_server *server,
                 unsigned int uam, char *username,
                 char *oldpasswd, char *newpasswd)
{
    struct afp_uam * u;

    if ((u = find_uam_by_bitmap(uam)) == NULL) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "afp_dopasswd -- Unknown UAM");
        return -1;
    }

    if (u->do_server_passwd == NULL) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "afp_dopasswd -- UAM %s does not support password change",
                       u->name);
        return kFPCallNotSupported;
    }

    return u->do_server_passwd(server, username, oldpasswd, newpasswd);
}
