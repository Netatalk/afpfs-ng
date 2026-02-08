/*
 *  uams.c
 *
 *  Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
 *  Copyright (C) 2007 Derrik Pates <dpates@dsdk12.net>
 *  Copyright (C) 2025-2026 Daniel Markstedt <daniel@mindani.net>
 *
 */

#include <string.h>
#include <stdlib.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#include <assert.h>	/* for assert() */
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBBSD
#include <bsd/string.h>
#endif

#include "dsi.h"
#include "afp.h"
#include "utils.h"
#include "uams_def.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
static int cleartxt_login(struct afp_server *server, char *username,
                          char *passwd);
static int cleartxt_passwd(struct afp_server *server, char *username,
                           char *passwd, char *newpasswd);
#ifdef HAVE_LIBGCRYPT
static int randnum_login(struct afp_server *server, char *username,
                         char *passwd);
static int randnum2_login(struct afp_server *server, char *username,
                          char *passwd);
static int randnum_passwd(struct afp_server *server, char *username,
                          char *passwd, char *newpasswd);
static int dhx_login(struct afp_server *server, char *username, char *passwd);
static int dhx_passwd(struct afp_server *server, char *username,
                      char *passwd, char *newpasswd);
static int dhx2_login(struct afp_server *server, char *username, char *passwd);
static int dhx2_passwd(struct afp_server *server, char *username,
                       char *passwd, char *newpasswd);
#endif /* HAVE_LIBGCRYPT */

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
    if (strlen(uam_names_list) +20 > UAMS_MAX_NAMES_LIST) {
        goto error;
    }

    if (strlen(uam_names_list)) {
        sprintf(uam_names_list + strlen(uam_names_list), ", %s", uam->name);
    } else {
        sprintf(uam_names_list + strlen(uam_names_list), "%s", uam->name);
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

/*
 *   Request block when using the Cleartext Password UAM:
 *
 *      +------------------+
 *      |     kFPLogin     |
 *      +------------------+
 *      |        0         |
 *      +------------------+
 *      |'Cleartxt Passwrd'|
 *      +------------------+
 *      /     UserName     /
 *      + - - - - - - - -  +
 *      |        0         |
 *      + - - - - - - - -  +
 *      |     Password     |
 *      |   in cleartext   |
 *      |    (8 bytes)     |
 *      +------------------+
 */
static int cleartxt_login(struct afp_server *server, char *username,
                          char *passwd)
{
    char *p, *ai = NULL;
    int len, ret;
    /* Pack the username and password into the authinfo struct. */
    p = ai = calloc(1, len = 1 + strlen(username) + 1 + 8);

    if (ai == NULL) {
        goto cleartxt_fail;
    }

    p += copy_to_pascal(p, username) + 1;

    if ((long)p & 0x1) {
        len--;
    } else {
        p++;
    }

    size_t passwd_len = strnlen(passwd, 8);

    if (passwd_len > 8) {
        passwd_len = 8;
    }

    memcpy(p, passwd, passwd_len);

    if (passwd_len < 8) {
        memset(p + passwd_len, 0, 8 - passwd_len);
    }

    /* Send the login request on to the server. */
    ret = afp_login(server, "Cleartxt Passwrd", ai, len, NULL);
    goto cleartxt_cleanup;
cleartxt_fail:
    ret = -1;
cleartxt_cleanup:
    free(ai);
    return ret;
}

/*
 *   Request block when changing the password for cleartext
 *
 *   AFP < 3.0:
 *      +------------------+
 *      | kFPChangePassword|
 *      +------------------+
 *      |        0         |
 *      +------------------+
 *      |'Cleartxt Passwrd'|
 *      +------------------+
 *      /     UserName     /
 *      + - - - - - - - -  +
 *      |        0         |
 *      + - - - - - - - -  +
 *      |   Old Password   |
 *      |   in cleartext   |
 *      |    (8 bytes)     |
 *      +------------------+
 *      |   New Password   |
 *      |   in cleartext   |
 *      |    (8 bytes)     |
 *      +------------------+
 *
 *   AFP >= 3.0:
 *      +------------------+
 *      | kFPChangePassword|
 *      +------------------+
 *      |        0         |
 *      +------------------+
 *      |'Cleartxt Passwrd'|
 *      +------------------+
 *      |      0x0000      |
 *      +------------------+
 *      |   Old Password   |
 *      |   in cleartext   |
 *      |    (8 bytes)     |
 *      +------------------+
 *      |   New Password   |
 *      |   in cleartext   |
 *      |    (8 bytes)     |
 *      +------------------+
 */
static int cleartxt_passwd(struct afp_server *server,
                           char *username, char *passwd, char *newpasswd)
{
    char *p, *ai = NULL;
    int len, ret;
    int afp_version = server->using_version->av_number;

    if (afp_version >= 30) {
        /* AFP 3.0+: username is not sent, just two zero bytes */
        len = 2 + 16;
        p = ai = calloc(1, len);

        if (ai == NULL) {
            goto cleartxt_fail;
        }

        /* Two zero bytes (username placeholder) */
        *p++ = 0;
        *p++ = 0;
    } else {
        /* AFP < 3.0: username as pascal string */
        len = 1 + strlen(username) + 1 + 16;
        ai = calloc(1, len);
        p = ai;

        if (ai == NULL) {
            goto cleartxt_fail;
        }

        p += copy_to_pascal(p, username) + 1;

        if ((long)p & 0x1) {
            len--;
        } else {
            p++;
        }
    }

    /* Copy old password (8 bytes, null-padded) */
    size_t old_passwd_len = strnlen(passwd, 8);

    if (old_passwd_len > 8) {
        old_passwd_len = 8;
    }

    memcpy(p, passwd, old_passwd_len);

    if (old_passwd_len < 8) {
        memset(p + old_passwd_len, 0, 8 - old_passwd_len);
    }

    p += 8;
    /* Copy new password (8 bytes, null-padded) */
    size_t new_passwd_len = strnlen(newpasswd, 8);

    if (new_passwd_len > 8) {
        new_passwd_len = 8;
    }

    memcpy(p, newpasswd, new_passwd_len);

    if (new_passwd_len < 8) {
        memset(p + new_passwd_len, 0, 8 - new_passwd_len);
    }

    /* Send the password change request to the server. */
    ret = afp_changepassword(server, "Cleartxt Passwrd", ai, len, NULL);
    goto cleartxt_cleanup;
cleartxt_fail:
    ret = -1;
cleartxt_cleanup:
    free(ai);
    return ret;
}

#ifdef HAVE_LIBGCRYPT

/*
 *   Request block when changing the password for Randnum Exchange
 *   (also used by 2-Way Randnum Exchange -- the key rotation used
 *   during login does not apply to password change)
 *
 *   AFP < 3.0:
 *      +------------------+
 *      | kFPChangePassword|
 *      +------------------+
 *      |        0         |
 *      +------------------+
 *      |'Randnum Exchange'|
 *      +------------------+
 *      /     UserName     /
 *      + - - - - - - - -  +
 *      |        0         |
 *      + - - - - - - - -  +
 *      |   Old Password   |
 *      |  DES-encrypted   |
 *      |  with new passwd |
 *      |    (8 bytes)     |
 *      +------------------+
 *      |   New Password   |
 *      |  DES-encrypted   |
 *      |  with old passwd |
 *      |    (8 bytes)     |
 *      +------------------+
 *
 *   AFP >= 3.0:
 *      +------------------+
 *      | kFPChangePassword|
 *      +------------------+
 *      |        0         |
 *      +------------------+
 *      |'Randnum Exchange'|
 *      +------------------+
 *      |      0x0000      |
 *      +------------------+
 *      |   Old Password   |
 *      |  DES-encrypted   |
 *      |  with new passwd |
 *      |    (8 bytes)     |
 *      +------------------+
 *      |   New Password   |
 *      |  DES-encrypted   |
 *      |  with old passwd |
 *      |    (8 bytes)     |
 *      +------------------+
 */
static int randnum_passwd(struct afp_server *server,
                          char *username, char *passwd, char *newpasswd)
{
    char *p, *ai = NULL;
    int len, ret;
    int afp_version = server->using_version->av_number;
    char old_buf[8], new_buf[8];
    gcry_cipher_hd_t ctx;
    gcry_error_t ctxerror;
    /* Prepare null-padded 8-byte copies of old and new passwords */
    memset(old_buf, 0, sizeof(old_buf));
    size_t old_len = strnlen(passwd, 8);
    memcpy(old_buf, passwd, old_len);
    memset(new_buf, 0, sizeof(new_buf));
    size_t new_len = strnlen(newpasswd, 8);
    memcpy(new_buf, newpasswd, new_len);

    if (afp_version >= 30) {
        /* AFP 3.0+: username is not sent, just two zero bytes */
        len = 2 + 16;
        p = ai = calloc(1, len);

        if (ai == NULL) {
            goto randnum_pw_fail;
        }

        /* Two zero bytes (username placeholder) */
        *p++ = 0;
        *p++ = 0;
    } else {
        /* AFP < 3.0: username as pascal string */
        len = 1 + strlen(username) + 1 + 16;
        ai = calloc(1, len);
        p = ai;

        if (ai == NULL) {
            goto randnum_pw_fail;
        }

        p += copy_to_pascal(p, username) + 1;

        if ((long)p & 0x1) {
            len--;
        } else {
            p++;
        }
    }

    /* DES-encrypt old password with new password as key */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_DES,
                                GCRY_CIPHER_MODE_ECB, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto randnum_pw_fail;
    }

    ctxerror = gcry_cipher_setkey(ctx, new_buf, 8);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        gcry_cipher_close(ctx);
        goto randnum_pw_fail;
    }

    ctxerror = gcry_cipher_encrypt(ctx, p, 8, old_buf, 8);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        gcry_cipher_close(ctx);
        goto randnum_pw_fail;
    }

    gcry_cipher_close(ctx);
    p += 8;
    /* DES-encrypt new password with old password as key */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_DES,
                                GCRY_CIPHER_MODE_ECB, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto randnum_pw_fail;
    }

    ctxerror = gcry_cipher_setkey(ctx, old_buf, 8);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        gcry_cipher_close(ctx);
        goto randnum_pw_fail;
    }

    ctxerror = gcry_cipher_encrypt(ctx, p, 8, new_buf, 8);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        gcry_cipher_close(ctx);
        goto randnum_pw_fail;
    }

    gcry_cipher_close(ctx);
    /* Send the password change request.
     * Both Randnum Exchange and 2-Way Randnum Exchange use the
     * "Randnum Exchange" UAM name for password changes. */
    ret = afp_changepassword(server, "Randnum Exchange", ai, len, NULL);
    goto randnum_pw_cleanup;
randnum_pw_fail:
    ret = -1;
randnum_pw_cleanup:
    memset(old_buf, 0, sizeof(old_buf));
    memset(new_buf, 0, sizeof(new_buf));
    free(ai);
    return ret;
}

/*
 * Transaction sequence for Random Number Exchange UAM:
 *
 * +------------------+  +---------------+  +---------------+
 * |     FPLogin      |  |      ID       |  |  FPLoginCont  |
 * +------------------+  +---------------+  +---------------+
 * |        0         |  | Random number |  |       0       |
 * +------------------+  |   (8 bytes)   |  +---------------+
 * |'Randnum Exchange'|  +---------------+  |      ID       |
 * +------------------+                     +---------------+
 * /     UserName     /                     | Random number |
 * +------------------+                     |   encrypted   |
 *                                          | with password |
 *                                          |   (8 bytes)   |
 *                                          +---------------+
 */
static int randnum_login(struct afp_server *server, char *username,
                         char *passwd)
{
    if (!gcry_check_version(UAM_NEED_LIBGCRYPT_VERSION)) {
        assert("libgrcypt initialization failed");
    }

    char *ai = NULL, *p;
    char key_buffer[8];
    int ai_len, ret;
    const int randnum_len = 8;
    gcry_cipher_hd_t ctx;
    gcry_error_t ctxerror;
    struct afp_rx_buffer rbuf;
    unsigned short ID;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "Starting Randnum Exchange authentication for user '%s'", username);
    p = rbuf.data = calloc(1, rbuf.maxsize = sizeof(ID) + randnum_len);

    if (rbuf.data == NULL) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum: Failed to allocate receive buffer");
        goto randnum_noctx_fail;
    }

    rbuf.size = 0;
    ai = calloc(1, ai_len = 1 + strlen(username));

    if (ai == NULL) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum: Failed to allocate authinfo buffer");
        goto randnum_noctx_fail;
    }

    copy_to_pascal(ai, username);
    /* Send the initial FPLogin request to the server. */
    ret = afp_login(server, "Randnum Exchange", ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "Randnum: FPLogin returned %d (expected %d for kFPAuthContinue), rbuf.size=%u",
                   ret, kFPAuthContinue, rbuf.size);

    if (ret != kFPAuthContinue) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Randnum: Server did not return kFPAuthContinue (got %d)", ret);
        goto randnum_noctx_cleanup;
    }

    /* For now, if the response block from the server isn't *exactly*
     * 10 bytes long (if we got kFPAuthContinue with this UAM, it
     * should never be any other size), die a horrible death. */
    if (rbuf.size != rbuf.maxsize) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum: Response size mismatch! Got %u bytes, expected %u bytes",
                       rbuf.size, rbuf.maxsize);
        assert("size of data returned during randnum auth process was wrong size, should be 10 bytes!");
    }

    /* Copy the relevant values out of the response block the server
     * sent to us. */
    ID = ntohs(*(unsigned short *)p);
    p += sizeof(ID);
    /* Establish encryption context for doing password encryption work. */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_DES,
                                GCRY_CIPHER_MODE_ECB, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum: Failed to create DES cipher context: %s",
                       gcry_strerror(ctxerror));
        goto randnum_noctx_fail;
    }

    /* Copy (up to 8 bytes of) the password into key_buffer. */
    memset(key_buffer, 0, sizeof(key_buffer));
    size_t passwd_len = strnlen(passwd, sizeof(key_buffer));
    memcpy(key_buffer, passwd, passwd_len);
    /* Set the provided password (now in key_buffer) as the encryption
     * key in our established context, for subsequent use to encrypt
     * the random number that the server sends us. */
    ctxerror = gcry_cipher_setkey(ctx, key_buffer, sizeof(key_buffer));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum: Failed to set DES key: %s",
                       gcry_strerror(ctxerror));
        goto randnum_fail;
    }

    /* Encrypt the random number data into the authinfo block for sending
     * to the server. */
    ctxerror = gcry_cipher_encrypt(ctx, p, randnum_len, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum: Failed to encrypt random number: %s",
                       gcry_strerror(ctxerror));
        goto randnum_fail;
    }

    /* Send the FPLoginCont to the server, containing the server's
     * random number encrypted with the password. */
    ret = afp_logincont(server, ID, p, randnum_len, NULL);
    goto randnum_cleanup;
randnum_noctx_fail:
    ret = -1;
    goto randnum_noctx_cleanup;
randnum_fail:
    ret = -1;
randnum_cleanup:
    /* Destroy the encryption context. */
    gcry_cipher_close(ctx);
randnum_noctx_cleanup:

    if (ret == kFPNoErr) {
        log_for_client(NULL, AFPFSD, LOG_INFO,
                       "Randnum Exchange authentication succeeded for user '%s'", username);
    } else {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Randnum Exchange authentication failed for user '%s' with code %d",
                       username, ret);
    }

    free(rbuf.data);
    free(ai);
    return ret;
}

/*
 * First transaction of Two-Way Random Number Exchange UAM:
 *
 * +------------------------+  +---------------+
 * |        FPLogin         |  |      ID       |
 * +------------------------+  +---------------+
 * |           0            |  | Random number |
 * +------------------------+  |   (8 bytes)   |
 * |'2-Way Randnum Exchange'|  +---------------+
 * +------------------------+
 * /        UserName        /
 * +------------------------+
 *
 * Second transaction of Two-Way Random Number Exchange UAM:
 *
 * +---------------+  +---------------+
 * |  FPLoginCont  |  |    Client     |
 * +---------------+  | random number |
 * |       0       |  |   encrypted   |
 * +---------------+  | with password |
 * |      ID       |  |   (8 bytes)   |
 * +---------------+  +---------------+
 * | Random number |
 * |   encrypted   |
 * | with password |
 * |   (8 bytes)   |
 * +---------------+
 * |    Client     |
 * | random number |
 * |   (8 bytes)   |
 * +---------------+
 */
static int randnum2_login(struct afp_server *server, char *username,
                          char *passwd)
{
    if (!gcry_check_version(UAM_NEED_LIBGCRYPT_VERSION)) {
        assert("libgrcypt initialization failed");
    }

    char *ai = NULL, *p = NULL, key_buffer[8], crypted[8];
    int ai_len, ret, carry;
    unsigned int i;
    size_t passwd_len;
    const int randnum_len = 8, crypted_len = 8;
    gcry_cipher_hd_t ctx;
    gcry_error_t ctxerror;
    struct afp_rx_buffer rbuf;
    unsigned short ID;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "Starting 2-Way Randnum Exchange authentication for user '%s'", username);
    p = rbuf.data = calloc(1, rbuf.maxsize = sizeof(ID) + 8);

    if (rbuf.data == NULL) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to allocate receive buffer");
        return -1;
    }

    rbuf.size = 0;
    ai = calloc(1, ai_len = 1 + strlen(username));

    if (ai == NULL) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to allocate authinfo buffer");
        goto randnum2_noctx_fail;
    }

    copy_to_pascal(ai, username);
    /* Send the initial FPLogin request to the server. */
    ret = afp_login(server, "2-Way Randnum Exchange", ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "Randnum2: FPLogin returned %d (expected %d for kFPAuthContinue), rbuf.size=%u",
                   ret, kFPAuthContinue, rbuf.size);

    if (ret != kFPAuthContinue) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Randnum2: Server did not return kFPAuthContinue (got %d)", ret);
        goto randnum2_noctx_cleanup;
    }

    /* For now, if the response block from the server isn't *exactly*
     * 10 bytes long (if we got kFPAuthContinue with this UAM, it
     * should never be any other size), die a horrible death. */
    if (rbuf.size != rbuf.maxsize) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Response size mismatch! Got %u bytes, expected %u bytes",
                       rbuf.size, rbuf.maxsize);
        assert("size of data returned during randnum2 auth process was wrong size, should be 10 bytes!");
    }

    /* Copy the relevant values out of the response block the server
     * sent to us. */
    ID = ntohs(*(unsigned short *)p);
    p += sizeof(ID);
    /* Establish encryption context for doing password encryption work. */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_DES,
                                GCRY_CIPHER_MODE_ECB, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to create DES cipher context: %s",
                       gcry_strerror(ctxerror));
        goto randnum2_noctx_fail;
    }

    /* Copy (up to 8 bytes of) the password into key_buffer, after
     * zeroing it out first. */
    memset(key_buffer, 0, sizeof(key_buffer));
    passwd_len = strnlen(passwd, sizeof(key_buffer));
    memcpy(key_buffer, passwd, passwd_len);
    /* Rotate each byte left one bit, carrying the high bit to the next. */
    carry = key_buffer[0] >> 7;

    for (i = 0; i < sizeof(key_buffer) - 1; i++) {
        key_buffer[i] = key_buffer[i] << 1 | key_buffer[i + 1] >> 7;
    }

    /* Wrap the high bit we copied right away to the end of the array. */
    key_buffer[i] = key_buffer[i] << 1 | carry;
    /* Set the provided password (now in key_buffer) as the encryption
     * key in our established context, for subsequent use to encrypt
     * the random number that the server sends us. */
    ctxerror = gcry_cipher_setkey(ctx, key_buffer, 8);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to set DES key: %s",
                       gcry_strerror(ctxerror));
        goto randnum2_fail;
    }

    /* Setup a new authinfo block for the FPLoginCont invocation. It will
     * contain the DES hashed password, followed by our chosen random
     * number, which the server will use to hash the password and then
     * send back to us for comparison. */
    ai = calloc(1, ai_len = crypted_len + randnum_len);

    if (ai == NULL) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to allocate second authinfo buffer");
        goto randnum2_fail;
    }

    /* Encrypt the random number data into the new authinfo block. */
    ctxerror = gcry_cipher_encrypt(ctx, ai, crypted_len, p, randnum_len);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to encrypt server's random: %s",
                       gcry_strerror(ctxerror));
        free(rbuf.data);
        rbuf.data = NULL;
        goto randnum2_fail;
    }

    free(rbuf.data);
    rbuf.data = NULL;
    p = ai + crypted_len;
    /* Use an internal gcrypt function to create the random number, so
     * we can do things (more) portably... */
    gcry_create_nonce(p, randnum_len);
    /* Make a place for the server's hashing of our password. */
    rbuf.data = calloc(1, rbuf.maxsize = 8);

    if (rbuf.data == NULL) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to allocate verification buffer");
        goto randnum2_fail;
    }

    rbuf.size = 0;
    /* Send the FPLoginCont to the server, containing the server's
     * random number encrypted with the password, and our random number.
     */
    ret = afp_logincont(server, ID, ai, ai_len, &rbuf);

    if (ret != kFPNoErr) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Randnum2: FPLoginCont failed with code %d", ret);
        goto randnum2_cleanup;
    }

    if (rbuf.size != rbuf.maxsize) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Verification response size mismatch! Got %u bytes, expected %u bytes",
                       rbuf.size, rbuf.maxsize);
        assert("size of data returned during randnum2 auth process was wrong size, should be 8 bytes!");
    }

    /* Encrypt our random number data into crypted[]. */
    ctxerror = gcry_cipher_encrypt(ctx, crypted, sizeof(crypted),
                                   p, randnum_len);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Failed to encrypt client random for verification: %s",
                       gcry_strerror(ctxerror));
        goto randnum2_fail;
    }

    /* If they didn't match, tell the caller that the user wasn't
     * authenticated, so it'll junk the connection. */
    if (memcmp(crypted, rbuf.data, sizeof(crypted)) != 0) {
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "Randnum2: Verification FAILED - encrypted client random does not match server's response");
        ret = kFPUserNotAuth;
    }

    goto randnum2_cleanup;
randnum2_noctx_fail:
    ret = -1;
    goto randnum2_noctx_cleanup;
randnum2_fail:
    ret = -1;
randnum2_cleanup:
    /* Destroy the encryption context. */
    gcry_cipher_close(ctx);
randnum2_noctx_cleanup:

    if (ret == kFPNoErr) {
        log_for_client(NULL, AFPFSD, LOG_INFO,
                       "2-Way Randnum Exchange authentication succeeded for user '%s'", username);
    } else {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "2-Way Randnum Exchange authentication failed for user '%s' with code %d",
                       username, ret);
    }

    free(rbuf.data);
    free(ai);
    return ret;
}

/* The initialization vectors are universally fixed. These are the values
 * documented by Apple.
 */
static const unsigned char dhx_c2siv[] = { 'L', 'W', 'a', 'l', 'l', 'a', 'c', 'e' };
static const unsigned char dhx_s2civ[] = { 'C', 'J', 'a', 'l', 'b', 'e', 'r', 't' };

/* The values of p and g are fixed for DHCAST128. */
static const unsigned char p_binary[] = { 0xba, 0x28, 0x73, 0xdf, 0xb0, 0x60,
                                          0x57, 0xd4, 0x3f, 0x20, 0x24, 0x74, 0x4c, 0xee, 0xe7, 0x5b
                                        };
static const unsigned char g_binary[] = { 0x07 };

/*
 * Transaction sequence for DHCAST128 UAM:
 *
 * +---------------+  +----------------+  +-----------------+
 * |    FPLogin    |  +       ID       +  |   FPLoginCont   |
 * +---------------+  +----------------+  +-----------------+
 * |       0       |  | Random number  |  |        0        |
 * +---------------+  |   (16 bytes)   |  +-----------------+
 * /  AFPVersion   /  +----------------+  +       ID        +
 * +---------------+  | Nonce followed |  +-----------------+
 * |  'DHCAST128'  |  | by 16 bytes of |  |   Nonce + 1,    |
 * +---------------+  | zero encrypted |  | followed by the |
 * /   Username    /  | by session key |  |  password, all  |
 * + - - - - - - - +  |   (32 bytes)   |  |  encrypted by   |
 * |       0       |  +----------------+  |   session key   |
 * + - - - - - - - +                      +-----------------|
 * | Random number |
 * |  (16 bytes)   |
 * +---------------+
 */
static int dhx_login(struct afp_server *server, char *username, char *passwd)
{
    if (!gcry_check_version(UAM_NEED_LIBGCRYPT_VERSION)) {
        assert("libgrcypt initialization failed");
    }

    char *ai = NULL;
    char *d = NULL;
    unsigned char Ra_binary[32], K_binary[16];
    int ai_len, ret;
    const int Ma_len = 16, Mb_len = 16, nonce_len = 16;
    gcry_mpi_t p, g, Ra, Ma, Mb, K, nonce, new_nonce;
    size_t len;
    struct afp_rx_buffer rbuf;
    unsigned short ID;
    gcry_cipher_hd_t ctx;
    gcry_error_t ctxerror;
    rbuf.data = NULL;
    /* Initialize all gcry_mpi_t variables, so they can all be uninitialized
     * in an orderly manner later. */
    p = gcry_mpi_new(0);
    g = gcry_mpi_new(0);
    Ra = gcry_mpi_new(0);
    Ma = gcry_mpi_new(0);
    Mb = gcry_mpi_new(0);
    K = gcry_mpi_new(0);
    nonce = gcry_mpi_new(0);
    new_nonce = gcry_mpi_new(0);
    /* Get p and g into a form that libgcrypt can use */
    gcry_mpi_scan(&p, GCRYMPI_FMT_USG, p_binary, sizeof(p_binary), NULL);
    gcry_mpi_scan(&g, GCRYMPI_FMT_USG, g_binary, sizeof(g_binary), NULL);
    /* Get random bytes for Ra. */
    gcry_randomize(Ra_binary, sizeof(Ra_binary), GCRY_STRONG_RANDOM);
    /* Translate the binary form of Ra into libgcrypt's preferred form */
    gcry_mpi_scan(&Ra, GCRYMPI_FMT_USG, Ra_binary, sizeof(Ra_binary), NULL);
    /* Ma = g^Ra mod p <- This is our "public" key, which we exchange
     * with the remote server to help make K, the session key. */
    gcry_mpi_powm(Ma, g, Ra, p);
    /* The first authinfo block, containing the username and our Ma value. */
    d = ai = calloc(1, ai_len = 1 + strlen(username) + 1 + Ma_len);

    if (ai == NULL) {
        goto dhx_noctx_fail;
    }

    d += copy_to_pascal(ai, username) + 1;

    if (((long)d) % 2) {
        d++;
    } else {
        ai_len--;
    }

    /* Extract Ma to send to the server for the exchange. */
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) d, Ma_len, &len, Ma);

    if (len < (size_t) Ma_len) {
        memmove(d + Ma_len - len, d, len);
        memset(d, 0, Ma_len - len);
    }

    /* 2 bytes for id, 16 bytes for Mb, 32 bytes of crypted message text */
    rbuf.maxsize = 2 + Mb_len + 32;
    rbuf.data = calloc(1, rbuf.maxsize);
    d = rbuf.data;

    if (rbuf.data == NULL) {
        goto dhx_noctx_fail;
    }

    rbuf.size = 0;
    /* Send the first FPLogin request, and see what happens. */
    ret = afp_login(server, "DHCAST128", ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;

    if (ret != kFPAuthContinue) {
        goto dhx_noctx_cleanup;
    }

    /* The block returned from the server should always be 50 bytes.
     * If it's not, for now, choke and die loudly so we know it. */
    if (rbuf.size != rbuf.maxsize) {
        assert("size of data returned during dhx auth process was wrong size, should be 50 bytes!");
    }

    /* Extract the transaction ID from the server's reply block. */
    ID = ntohs(*(unsigned short *)d);
    d += sizeof(ID);
    /* Now, extract Mb (the server's "public key" part) directly into
     * a gcry_mpi_t. */
    gcry_mpi_scan(&Mb, GCRYMPI_FMT_USG, d, Mb_len, NULL);
    d += Mb_len;
    /* d now points to the ciphertext, which we'll decrypt in a bit. */
    /* K = Mb^Ra mod p <- This nets us the "session key", which we
     * actually use to encrypt and decrypt data. */
    gcry_mpi_powm(K, Mb, Ra, p);
    gcry_mpi_print(GCRYMPI_FMT_USG, K_binary, sizeof(K_binary), &len, K);

    if (len < sizeof(K_binary)) {
        memmove(K_binary + (sizeof(K_binary) - len), K_binary, len);
        memset(K_binary, 0, sizeof(K_binary) - len);
    }

    /* FIXME: To support the Reconnect UAM, we need to stash this key
     * somewhere in the session data. We'll worry about doing that
     * later, but this would be a prime spot to do that. */
    /* Set up our encryption context. */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_CAST5,
                                GCRY_CIPHER_MODE_CBC, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_noctx_fail;
    }

    /* Set the binary form of K as our key for this encryption context. */
    ctxerror = gcry_cipher_setkey(ctx, K_binary, sizeof(K_binary));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_fail;
    }

    /* Set the initialization vector for server->client transfer. */
    ctxerror = gcry_cipher_setiv(ctx, dhx_s2civ, sizeof(dhx_s2civ));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_fail;
    }

    /* The plaintext will hold the nonce (16 bytes) and the server's
     * signature (16 bytes - we don't actually look at it though). */
    len = nonce_len + 16;
    /* Decrypt the ciphertext from the server. */
    ctxerror = gcry_cipher_decrypt(ctx, d, len, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_fail;
    }

    /* Pull the binary form of the nonce into a form that libgcrypt can
     * deal with. */
    gcry_mpi_scan(&nonce, GCRYMPI_FMT_USG, d, nonce_len, NULL);
    /* NOTE: The following 16 bytes of plaintext, which the docs indicate
     * as the server signature, will always contain just 0 values - Apple's
     * docs claim that due to an error in an early implementation, it will
     * always be that way. No point in looking at that. */
    /* d still points into rbuf.data, which is no longer needed. */
    free(rbuf.data);
    rbuf.data = NULL;
    /* Increment the nonce by 1 for sending back to the server. */
    gcry_mpi_add_ui(new_nonce, nonce, 1);
    /* New plaintext is 16 bytes of nonce, and (up to) 64 bytes of
     * password (filled out with NULL values). */
    d = ai = calloc(1, ai_len = nonce_len + 64);

    if (ai == NULL) {
        goto dhx_fail;
    }

    /* Pull the incremented nonce value back out into binary form. */
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) d, nonce_len, &len,
                   new_nonce);

    if (len < (size_t) nonce_len) {
        memmove(d + nonce_len - len, d, len);
        memset(d, 0, nonce_len - len);
    }

    d += nonce_len;
    /* Copy the user's password into the plaintext. */
    strlcpy(d, passwd, 64);
    /* Set the initialization vector for client->server transfer. */
    ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_c2siv));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_fail;
    }

    /* Encrypt the plaintext to create our new authinfo block. */
    ctxerror = gcry_cipher_encrypt(ctx, ai, ai_len, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_fail;
    }

    /* Send the FPLoginCont with the new authinfo block, sit back,
     * cross fingers... */
    ret = afp_logincont(server, ID, ai, ai_len, NULL);
    goto dhx_cleanup;
dhx_noctx_fail:
    ret = -1;
    goto dhx_noctx_cleanup;
dhx_fail:
    ret = -1;
dhx_cleanup:
    gcry_cipher_close(ctx);
dhx_noctx_cleanup:
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(Ra);
    gcry_mpi_release(Ma);
    gcry_mpi_release(Mb);
    gcry_mpi_release(K);
    gcry_mpi_release(nonce);
    gcry_mpi_release(new_nonce);
    free(ai);
    free(rbuf.data);
    return ret;
}

/*
 *   Password change for DHCAST128 UAM (two-round DH exchange):
 *
 *   Round 1 (key exchange):
 *      Client sends:
 *      +------------------+
 *      | kFPChangePassword|
 *      +------------------+
 *      |        0         |
 *      +------------------+
 *      |   'DHCAST128'    |
 *      +------------------+
 *      /  UserName/0x0000 /
 *      +------------------+
 *      |  sessid = 0x0000 |
 *      +------------------+
 *      |   Ma (16 bytes)  |
 *      +------------------+
 *
 *      Server responds with kFPAuthContinue:
 *      +------------------+
 *      |  sessid (2 bytes)|
 *      +------------------+
 *      |   Mb (16 bytes)  |
 *      +------------------+
 *      |  Encrypted block |
 *      | [nonce + 16 zero |
 *      |  bytes] (32 bytes|
 *      |  CAST5-CBC, K,   |
 *      |  "CJalbert" IV)  |
 *      +------------------+
 *
 *   Round 2 (password submission):
 *      Client sends:
 *      +------------------+
 *      | kFPChangePassword|
 *      +------------------+
 *      |        0         |
 *      +------------------+
 *      |   'DHCAST128'    |
 *      +------------------+
 *      /  UserName/0x0000 /
 *      +------------------+
 *      |  sessid (2 bytes)|
 *      +------------------+
 *      |  Encrypted block |
 *      | [nonce+1(16) +   |
 *      |  new pw (64) +   |
 *      |  old pw (64)]    |
 *      | (144 bytes,      |
 *      |  CAST5-CBC, K,   |
 *      |  "LWallace" IV)  |
 *      +------------------+
 */
static int dhx_passwd(struct afp_server *server,
                      char *username, char *passwd, char *newpasswd)
{
    if (!gcry_check_version(UAM_NEED_LIBGCRYPT_VERSION)) {
        assert("libgrcypt initialization failed");
    }

    char *ai = NULL;
    char *d = NULL;
    unsigned char Ra_binary[32], K_binary[16];
    int ai_len, ret;
    const int Ma_len = 16, Mb_len = 16, nonce_len = 16;
    const int changepw_plaintext_len = nonce_len + 64 + 64; /* 144 bytes */
    gcry_mpi_t p, g, Ra, Ma, Mb, K, nonce, new_nonce;
    size_t len;
    struct afp_rx_buffer rbuf;
    unsigned short ID;
    gcry_cipher_hd_t ctx;
    gcry_error_t ctxerror;
    int afp_version = server->using_version->av_number;
    int username_overhead;
    rbuf.data = NULL;
    /* Initialize all gcry_mpi_t variables */
    p = gcry_mpi_new(0);
    g = gcry_mpi_new(0);
    Ra = gcry_mpi_new(0);
    Ma = gcry_mpi_new(0);
    Mb = gcry_mpi_new(0);
    K = gcry_mpi_new(0);
    nonce = gcry_mpi_new(0);
    new_nonce = gcry_mpi_new(0);
    /* Get p and g into a form that libgcrypt can use */
    gcry_mpi_scan(&p, GCRYMPI_FMT_USG, p_binary, sizeof(p_binary), NULL);
    gcry_mpi_scan(&g, GCRYMPI_FMT_USG, g_binary, sizeof(g_binary), NULL);
    /* Get random bytes for Ra */
    gcry_randomize(Ra_binary, sizeof(Ra_binary), GCRY_STRONG_RANDOM);
    gcry_mpi_scan(&Ra, GCRYMPI_FMT_USG, Ra_binary, sizeof(Ra_binary), NULL);
    /* Ma = g^Ra mod p -- our "public" key */
    gcry_mpi_powm(Ma, g, Ra, p);

    /*
     * Round 1: Send sessid=0 + Ma, receive sessid + Mb + encrypted nonce
     */
    if (afp_version >= 30) {
        /* AFP 3.0+: two zero bytes instead of username */
        username_overhead = 2;
        ai_len = username_overhead + 2 + Ma_len; /* 0x0000 + sessid + Ma */
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx_pw_noctx_fail;
        }

        *d++ = 0;
        *d++ = 0;
    } else {
        /* AFP < 3.0: username as pascal string */
        int pascal_len = 1 + strlen(username);
        int pad = (pascal_len & 1) ? 0 : 1;
        username_overhead = pascal_len + pad;
        ai_len = username_overhead + 2 + Ma_len;
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx_pw_noctx_fail;
        }

        d += copy_to_pascal(d, username) + 1;

        if ((long)d & 0x1) {
            ai_len--;
        } else {
            d++;
        }
    }

    /* sessid = 0 for initialization */
    *d++ = 0;
    *d++ = 0;
    /* Extract Ma to send to the server */
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)d, Ma_len, &len, Ma);

    if (len < (size_t)Ma_len) {
        memmove(d + Ma_len - len, d, len);
        memset(d, 0, Ma_len - len);
    }

    /* Receive: 2 bytes ID + 16 bytes Mb + 32 bytes encrypted block = 50 */
    rbuf.maxsize = 2 + Mb_len + 32;
    rbuf.data = calloc(1, rbuf.maxsize);
    d = rbuf.data;

    if (rbuf.data == NULL) {
        goto dhx_pw_noctx_fail;
    }

    rbuf.size = 0;
    /* Send round 1 */
    ret = afp_changepassword(server, "DHCAST128", ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;

    if (ret != kFPAuthContinue) {
        goto dhx_pw_noctx_cleanup;
    }

    if (rbuf.size != rbuf.maxsize) {
        goto dhx_pw_noctx_fail;
    }

    /* Extract transaction ID */
    ID = ntohs(*(unsigned short *)d);
    d += sizeof(ID);
    /* Extract Mb (server's "public key") */
    gcry_mpi_scan(&Mb, GCRYMPI_FMT_USG, d, Mb_len, NULL);
    d += Mb_len;
    /* d now points to the 32-byte encrypted block */
    /* K = Mb^Ra mod p -- the session key */
    gcry_mpi_powm(K, Mb, Ra, p);
    gcry_mpi_print(GCRYMPI_FMT_USG, K_binary, sizeof(K_binary), &len, K);

    if (len < sizeof(K_binary)) {
        memmove(K_binary + (sizeof(K_binary) - len), K_binary, len);
        memset(K_binary, 0, sizeof(K_binary) - len);
    }

    /* Set up encryption context to decrypt the nonce */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_CAST5,
                                GCRY_CIPHER_MODE_CBC, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_pw_noctx_fail;
    }

    ctxerror = gcry_cipher_setkey(ctx, K_binary, sizeof(K_binary));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_pw_fail;
    }

    /* Decrypt with server->client IV */
    ctxerror = gcry_cipher_setiv(ctx, dhx_s2civ, sizeof(dhx_s2civ));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_pw_fail;
    }

    /* Decrypt the 32-byte block: nonce (16) + signature (16 zeros) */
    ctxerror = gcry_cipher_decrypt(ctx, d, nonce_len + 16, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_pw_fail;
    }

    /* Extract nonce and increment by 1 */
    gcry_mpi_scan(&nonce, GCRYMPI_FMT_USG, d, nonce_len, NULL);
    gcry_mpi_add_ui(new_nonce, nonce, 1);
    free(rbuf.data);
    rbuf.data = NULL;

    /*
     * Round 2: Send sessid + encrypted [nonce+1 + new_pw + old_pw]
     */
    if (afp_version >= 30) {
        ai_len = 2 + 2 + changepw_plaintext_len;
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx_pw_fail;
        }

        *d++ = 0;
        *d++ = 0;
    } else {
        int pascal_len = 1 + strlen(username);
        int pad = (pascal_len & 1) ? 0 : 1;
        username_overhead = pascal_len + pad;
        ai_len = username_overhead + 2 + changepw_plaintext_len;
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx_pw_fail;
        }

        d += copy_to_pascal(d, username) + 1;

        if ((long)d & 0x1) {
            ai_len--;
        } else {
            d++;
        }
    }

    /* Session ID from server */
    *(unsigned short *)d = htons(ID);
    d += sizeof(ID);
    /* Build plaintext: nonce+1 (16) + new password (64) + old password (64) */
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)d, nonce_len, &len,
                   new_nonce);

    if (len < (size_t)nonce_len) {
        memmove(d + nonce_len - len, d, len);
        memset(d, 0, nonce_len - len);
    }

    d += nonce_len;
    /* New password (64 bytes, null-padded) */
    memset(d, 0, 64);
    strlcpy(d, newpasswd, 64);
    d += 64;
    /* Old password (64 bytes, null-padded) */
    memset(d, 0, 64);
    strlcpy(d, passwd, 64);
    /* Encrypt the plaintext with client->server IV */
    /* d currently points into ai; reset to start of encrypted portion */
    d = ai + (ai_len - changepw_plaintext_len);
    ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_c2siv));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_pw_fail;
    }

    ctxerror = gcry_cipher_encrypt(ctx, d, changepw_plaintext_len, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx_pw_fail;
    }

    /* Send round 2 */
    ret = afp_changepassword(server, "DHCAST128", ai, ai_len, NULL);
    goto dhx_pw_cleanup;
dhx_pw_noctx_fail:
    ret = -1;
    goto dhx_pw_noctx_cleanup;
dhx_pw_fail:
    ret = -1;
dhx_pw_cleanup:
    gcry_cipher_close(ctx);
dhx_pw_noctx_cleanup:
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(Ra);
    gcry_mpi_release(Ma);
    gcry_mpi_release(Mb);
    gcry_mpi_release(K);
    gcry_mpi_release(nonce);
    gcry_mpi_release(new_nonce);
    free(ai);
    free(rbuf.data);
    return ret;
}

static int dhx2_login(struct afp_server *server, char *username, char *passwd)
{
    if (!gcry_check_version(UAM_NEED_LIBGCRYPT_VERSION)) {
        assert("libgrcypt initialization failed");
    }

    gcry_mpi_t p, g, Ma, Mb, Ra, K, nonce, new_nonce;
    char *ai = NULL, *d, *Ra_binary = NULL, *K_binary = NULL;
    char *K_hash = NULL, nonce_binary[16];
    int ai_len, hash_len, ret;
    const int g_len = 4;
    size_t len;
    struct afp_rx_buffer rbuf;
    unsigned short ID, bignum_len;
    gcry_cipher_hd_t ctx;
    gcry_error_t ctxerror;
    rbuf.data = NULL;
    p = gcry_mpi_new(0);
    g = gcry_mpi_new(0);
    Ra = gcry_mpi_new(0);
    Ma = gcry_mpi_new(0);
    Mb = gcry_mpi_new(0);
    K = gcry_mpi_new(0);
    nonce = gcry_mpi_new(0);
    new_nonce = gcry_mpi_new(0);
    ai_len = strlen(username) + 1;
    ai = calloc(1, ai_len);
    d = ai;

    if (ai == NULL) {
        goto dhx2_noctx_fail;
    }

    d += copy_to_pascal(ai, username) + 1;
    /* Reply block will contain:
     *   Transaction ID (2 bytes, MSB)
     *   g (4 bytes, MSB)
     *   length of large values in bytes (2 bytes, MSB)
     *   p (minimum 64 bytes, indicated by length value, MSB)
     *   Mb (minimum 64 bytes, indicated by length value, MSB)
     * We'll reserve 256 bytes for each of p and Mb.
     * FIXME: We need to retool this to handle any length for p and Mb;
     * I've only ever seen it be 64 bytes, but it could easily be larger. */
    rbuf.maxsize = 2 + 4 + 2 + 256 * 2;
    rbuf.data = calloc(1, rbuf.maxsize);
    d = rbuf.data;

    if (rbuf.data == NULL) {
        goto dhx2_noctx_fail;
    }

    rbuf.size = 0;
    /* Send the initial request in the login sequence. */
    ret = afp_login(server, "DHX2", ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;

    if (ret != kFPAuthContinue) {
        goto dhx2_noctx_cleanup;
    }

    /* Pull the transaction ID out of the reply block. */
    ID = ntohs(*(unsigned short *)d);
    d += sizeof(ID);
    /* Pull the value of g out of the reply block and directly into an
     * gcry_mpi_t container for later use with libgcrypt. */
    gcry_mpi_scan(&g, GCRYMPI_FMT_USG, d, g_len, NULL);
    d += g_len;
    bignum_len = ntohs(*(unsigned short *)d);
    d += sizeof(bignum_len);

    if (bignum_len > 256) {
        assert("server indicates large number length too large for us (> 256 bytes)?");
    }

    /* Extract p into an gcry_mpi_t. */
    gcry_mpi_scan(&p, GCRYMPI_FMT_USG, d, bignum_len, NULL);
    d += bignum_len;
    /* Extract Mb into an gcry_mpi_t. */
    gcry_mpi_scan(&Mb, GCRYMPI_FMT_USG, d, bignum_len, NULL);
    free(rbuf.data);
    rbuf.data = NULL;
    Ra_binary = calloc(1, bignum_len);

    if (Ra_binary == NULL) {
        goto dhx2_noctx_fail;
    }

    /* Get random bytes for Ra. */
    gcry_randomize(Ra_binary, bignum_len, GCRY_STRONG_RANDOM);
    /* Pull the random value we just read into an gcry_mpi_t so we can do
     * large-value exponentiation, and generate our Ma. */
    gcry_mpi_scan(&Ra, GCRYMPI_FMT_USG, Ra_binary, bignum_len, NULL);
    free(Ra_binary);
    Ra_binary = NULL;
    /* Ma = g^Ra mod p <- This is our "public" key, which we exchange
     * with the remote server to help make K, the session key. */
    gcry_mpi_powm(Ma, g, Ra, p);
    /* K = Mb^Ra mod p <- This nets us the "session key", which we
     * actually use to encrypt and decrypt data. */
    gcry_mpi_powm(K, Mb, Ra, p);
    K_binary = calloc(1, bignum_len);

    if (K_binary == NULL) {
        goto dhx2_noctx_fail;
    }

    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) K_binary, bignum_len, &len,
                   K);

    if (len < bignum_len) {
        memmove(K_binary + bignum_len - len, K_binary, len);
        memset(K_binary, 0, bignum_len - len);
    }

    /* Use a one-shot hash function to generate the MD5 hash of K. */
    hash_len = gcry_md_get_algo_dlen(GCRY_MD_MD5);
    K_hash = calloc(1, hash_len);

    if (K_hash == NULL) {
        goto dhx2_noctx_fail;
    }

    gcry_md_hash_buffer(GCRY_MD_MD5, K_hash, K_binary, bignum_len);
    /* FIXME: To support the Reconnect UAM, we need to stash this key
     * somewhere in the session data. We'll worry about doing that
     * later, but this would be a prime spot to do that. */
    /* Use an internal gcrypt function to create the random number, so
     * we can do things (more) portably... */
    gcry_create_nonce(nonce_binary, sizeof(nonce_binary));
    /* Set up our encryption context. */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_CAST5,
                                GCRY_CIPHER_MODE_CBC, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_noctx_fail;
    }

    /* Set the hashed form of K as our key for this encryption context. */
    ctxerror = gcry_cipher_setkey(ctx, K_hash, hash_len);
    free(K_hash);
    K_hash = NULL;

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_fail;
    }

    /* Set the initialization vector for client->server transfer. */
    ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_s2civ));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_fail;
    }

    /* The new authinfo block will contain Ma (our "public" key part) and
     * the encrypted form of our nonce. */
    d = ai = calloc(1, ai_len = bignum_len + sizeof(nonce_binary));

    if (ai == NULL) {
        goto dhx2_fail;
    }

    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) d, bignum_len, &len, Ma);

    if (len < bignum_len) {
        memmove(d + bignum_len - len, d, len);
        memset(d, 0, bignum_len - len);
    }

    d += bignum_len;
    /* Encrypt our nonce into the new authinfo block. */
    ctxerror = gcry_cipher_encrypt(ctx, d, sizeof(nonce_binary),
                                   nonce_binary, sizeof(nonce_binary));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_fail;
    }

    /* Reply block will contain ID, then the encrypted form of our
     * nonce + 1 and the server's nonce. */
    d = rbuf.data = calloc(1, rbuf.maxsize = sizeof(ID) +
                           sizeof(nonce_binary) * 2);

    if (rbuf.data == NULL) {
        goto dhx2_fail;
    }

    rbuf.size = 0;
    ret = afp_logincont(server, ID, ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;

    if (ret != kFPAuthContinue) {
        goto dhx2_cleanup;
    }

    /* Get the new transaction ID for the last portion of the exchange. */
    ID = ntohs(*(unsigned short *)d);
    d += sizeof(ID);
    /* Set the initialization vector for server->client transfer. */
    ctxerror = gcry_cipher_setiv(ctx, dhx_s2civ, sizeof(dhx_s2civ));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_fail;
    }

    len = rbuf.maxsize - sizeof(ID);
    /* Decrypt the ciphertext from the server. */
    ctxerror = gcry_cipher_decrypt(ctx, d, len, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_fail;
    }

    /* Pull our nonce into an gcry_mpi_t so we can operate. */
    gcry_mpi_scan(&nonce, GCRYMPI_FMT_USG, nonce_binary, sizeof(nonce_binary),
                  NULL);
    /* Increment our nonce by one. */
    gcry_mpi_add_ui(new_nonce, nonce, 1);
    /* Pull the incremented nonce back out into binary form. */
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) nonce_binary,
                   sizeof(nonce_binary), &len,
                   new_nonce);

    if (len < sizeof(nonce_binary)) {
        memmove(nonce_binary + sizeof(nonce_binary) - len,
                nonce_binary, len);
        memset(nonce_binary, 0, sizeof(nonce_binary) - len);
    }

    /* Compare our incremented nonce to the server's incremented copy
     * of our original nonce value; if they don't match, something
     * terrible has happened. */
    if (memcmp(nonce_binary, d, 16) != 0) {
        assert("nonce check failed while running dhx2 authentication");
    }

    d += sizeof(nonce_binary);
    /* Pull the server's nonce value into an gcry_mpi_t. */
    gcry_mpi_scan(&nonce, GCRYMPI_FMT_USG, d, sizeof(nonce_binary), NULL);
    /* d still points into rbuf.data; let's dispose of it safely. */
    free(rbuf.data);
    rbuf.data = NULL;
    /* Increment the server's nonce by one. */
    gcry_mpi_add_ui(new_nonce, nonce, 1);
    /* The new plaintext will need 16 bytes for the server nonce (after
     * incrementing), followed by 256 bytes of null-filled space for the
     * user's password. */
    d = ai = calloc(1, ai_len = sizeof(nonce_binary) + 256);

    if (ai == NULL) {
        goto dhx2_fail;
    }

    /* Extract the binary form of the incremented server nonce into
     * the plaintext buffer. */
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *) d, sizeof(nonce_binary), &len,
                   new_nonce);

    if (len < sizeof(nonce_binary)) {
        memmove(d + sizeof(nonce_binary) - len, d, len);
        memset(d, 0, sizeof(nonce_binary) - len);
    }

    d += sizeof(nonce_binary);
    /* Copy the user's password into the plaintext buffer. */
    strlcpy(d, passwd, 256);
    /* Set the initialization vector for client->server transfer. */
    ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_s2civ));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_fail;
    }

    /* Encrypt our nonce into the new authinfo block. */
    ctxerror = gcry_cipher_encrypt(ctx, ai, ai_len, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_fail;
    }

    /* Send the FPLoginCont with the new authinfo block, sit back,
     * cross fingers... */
    ret = afp_logincont(server, ID, ai, ai_len, NULL);
    goto dhx2_cleanup;
dhx2_noctx_fail:
    ret = -1;
    goto dhx2_noctx_cleanup;
dhx2_fail:
    ret = -1;
dhx2_cleanup:
    gcry_cipher_close(ctx);
dhx2_noctx_cleanup:
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(Ra);
    gcry_mpi_release(Ma);
    gcry_mpi_release(Mb);
    gcry_mpi_release(K);
    gcry_mpi_release(nonce);
    gcry_mpi_release(new_nonce);
    free(Ra_binary);
    free(K_binary);
    free(K_hash);
    free(ai);
    free(rbuf.data);
    return ret;
}

/*
 *   Password change for DHX2 UAM (three-round DH exchange):
 *
 *   Round 1 (DH parameter exchange):
 *      Client sends FPChangePassword with username only (no payload).
 *      Server responds with kFPAuthContinue:
 *        ID(2) + g(4) + bignum_len(2) + p(bignum_len) + Ma(bignum_len)
 *
 *   Round 2 (key exchange + nonce):
 *      Client computes Mb = g^Rb mod p, K = Ma^Rb mod p, K_hash = MD5(K)
 *      Client sends:  username + ID(2) + Mb(bignum_len) + enc_nonce(16)
 *      Server responds with kFPAuthContinue:
 *        ID+1(2) + encrypted[clientNonce+1(16) + serverNonce(16)]
 *
 *   Round 3 (password submission):
 *      Client sends:  username + ID+1(2) +
 *        encrypted[serverNonce+1(16) + new_pw(256) + old_pw(256)]
 *      Server responds with success or error.
 */
static int dhx2_passwd(struct afp_server *server,
                       char *username, char *passwd, char *newpasswd)
{
    if (!gcry_check_version(UAM_NEED_LIBGCRYPT_VERSION)) {
        assert("libgrcypt initialization failed");
    }

    gcry_mpi_t p, g, Ma, Mb, Rb, K, clientNonce, new_clientNonce;
    gcry_mpi_t serverNonce, new_serverNonce;
    char *ai = NULL, *d, *Rb_binary = NULL, *K_binary = NULL;
    char *K_hash = NULL, nonce_binary[16];
    int ai_len, hash_len, ret;
    const int g_len = 4;
    size_t len;
    struct afp_rx_buffer rbuf;
    unsigned short ID;
    unsigned short bignum_len;
    gcry_cipher_hd_t ctx;
    gcry_error_t ctxerror;
    int afp_version = server->using_version->av_number;
    int have_ctx = 0;
    rbuf.data = NULL;
    p = gcry_mpi_new(0);
    g = gcry_mpi_new(0);
    Rb = gcry_mpi_new(0);
    Ma = gcry_mpi_new(0);
    Mb = gcry_mpi_new(0);
    K = gcry_mpi_new(0);
    clientNonce = gcry_mpi_new(0);
    new_clientNonce = gcry_mpi_new(0);
    serverNonce = gcry_mpi_new(0);
    new_serverNonce = gcry_mpi_new(0);

    /*
     * Round 1: Send username only, receive DH parameters
     */
    if (afp_version >= 30) {
        ai_len = 2;
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx2_pw_noctx_fail;
        }

        *d++ = 0;
        *d++ = 0;
    } else {
        ai_len = strlen(username) + 1;
        ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx2_pw_noctx_fail;
        }

        copy_to_pascal(ai, username);
    }

    /* Receive: ID(2) + g(4) + bignum_len(2) + p(bignum_len) + Ma(bignum_len)
     * Reserve 256 bytes each for p and Ma */
    rbuf.maxsize = 2 + 4 + 2 + 256 * 2;
    rbuf.data = calloc(1, rbuf.maxsize);
    d = rbuf.data;

    if (rbuf.data == NULL) {
        goto dhx2_pw_noctx_fail;
    }

    rbuf.size = 0;
    ret = afp_changepassword(server, "DHX2", ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;

    if (ret != kFPAuthContinue) {
        goto dhx2_pw_noctx_cleanup;
    }

    /* Parse server's DH parameters */
    ID = ntohs(*(unsigned short *)d);
    d += sizeof(ID);
    gcry_mpi_scan(&g, GCRYMPI_FMT_USG, d, g_len, NULL);
    d += g_len;
    bignum_len = ntohs(*(unsigned short *)d);
    d += sizeof(bignum_len);

    if (bignum_len > 256) {
        goto dhx2_pw_noctx_fail;
    }

    /* Extract p and Ma (server's public key) */
    gcry_mpi_scan(&p, GCRYMPI_FMT_USG, d, bignum_len, NULL);
    d += bignum_len;
    gcry_mpi_scan(&Ma, GCRYMPI_FMT_USG, d, bignum_len, NULL);
    free(rbuf.data);
    rbuf.data = NULL;
    /* Generate our random Rb and compute Mb = g^Rb mod p */
    Rb_binary = calloc(1, bignum_len);

    if (Rb_binary == NULL) {
        goto dhx2_pw_noctx_fail;
    }

    gcry_randomize(Rb_binary, bignum_len, GCRY_STRONG_RANDOM);
    gcry_mpi_scan(&Rb, GCRYMPI_FMT_USG, Rb_binary, bignum_len, NULL);
    free(Rb_binary);
    Rb_binary = NULL;
    gcry_mpi_powm(Mb, g, Rb, p);
    gcry_mpi_powm(K, Ma, Rb, p);
    K_binary = calloc(1, bignum_len);

    if (K_binary == NULL) {
        goto dhx2_pw_noctx_fail;
    }

    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)K_binary, bignum_len,
                   &len, K);

    if (len < bignum_len) {
        memmove(K_binary + bignum_len - len, K_binary, len);
        memset(K_binary, 0, bignum_len - len);
    }

    hash_len = gcry_md_get_algo_dlen(GCRY_MD_MD5);
    K_hash = calloc(1, hash_len);

    if (K_hash == NULL) {
        goto dhx2_pw_noctx_fail;
    }

    gcry_md_hash_buffer(GCRY_MD_MD5, K_hash, K_binary, bignum_len);
    free(K_binary);
    K_binary = NULL;
    /* Generate client nonce */
    gcry_create_nonce(nonce_binary, sizeof(nonce_binary));
    /* Set up encryption context */
    ctxerror = gcry_cipher_open(&ctx, GCRY_CIPHER_CAST5,
                                GCRY_CIPHER_MODE_CBC, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_noctx_fail;
    }

    have_ctx = 1;
    ctxerror = gcry_cipher_setkey(ctx, K_hash, hash_len);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_fail;
    }

    /* Encrypt client nonce with C2S IV */
    ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_c2siv));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_fail;
    }

    /*
     * Round 2: Send Mb + encrypted nonce, receive encrypted nonces
     */
    if (afp_version >= 30) {
        ai_len = 2 + 2 + bignum_len + sizeof(nonce_binary);
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx2_pw_fail;
        }

        *d++ = 0;
        *d++ = 0;
    } else {
        int pascal_len = 1 + strlen(username);
        int pad = (pascal_len & 1) ? 0 : 1;
        ai_len = pascal_len + pad + 2 + bignum_len + sizeof(nonce_binary);
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx2_pw_fail;
        }

        d += copy_to_pascal(d, username) + 1;

        if ((long)d & 0x1) {
            ai_len--;
        } else {
            d++;
        }
    }

    /* Session ID */
    *(unsigned short *)d = htons(ID);
    d += 2;
    /* Mb (client's public key) */
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)d, bignum_len, &len, Mb);

    if (len < bignum_len) {
        memmove(d + bignum_len - len, d, len);
        memset(d, 0, bignum_len - len);
    }

    d += bignum_len;
    /* Encrypted client nonce */
    ctxerror = gcry_cipher_encrypt(ctx, d, sizeof(nonce_binary),
                                   nonce_binary, sizeof(nonce_binary));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_fail;
    }

    /* Receive 34 bytes: 2-byte ID followed by a 32-byte encrypted block
     * containing the incremented client nonce (16 bytes) and server nonce (16 bytes) */
    rbuf.maxsize = 2 + 32;
    rbuf.data = calloc(1, rbuf.maxsize);
    d = rbuf.data;

    if (rbuf.data == NULL) {
        goto dhx2_pw_fail;
    }

    rbuf.size = 0;
    ret = afp_changepassword(server, "DHX2", ai, ai_len, &rbuf);
    free(ai);
    ai = NULL;

    if (ret != kFPAuthContinue) {
        goto dhx2_pw_cleanup;
    }

    /* Get the new transaction ID */
    ID = ntohs(*(unsigned short *)d);
    d += 2;
    /* Decrypt server's response with S2C IV */
    ctxerror = gcry_cipher_setiv(ctx, dhx_s2civ, sizeof(dhx_s2civ));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_fail;
    }

    ctxerror = gcry_cipher_decrypt(ctx, d, 32, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_fail;
    }

    /* Verify clientNonce + 1 */
    gcry_mpi_scan(&clientNonce, GCRYMPI_FMT_USG, nonce_binary,
                  sizeof(nonce_binary), NULL);
    gcry_mpi_add_ui(new_clientNonce, clientNonce, 1);
    gcry_mpi_t retNonce;
    retNonce = gcry_mpi_new(0);
    gcry_mpi_scan(&retNonce, GCRYMPI_FMT_USG, d, 16, NULL);

    if (gcry_mpi_cmp(new_clientNonce, retNonce) != 0) {
        gcry_mpi_release(retNonce);
        goto dhx2_pw_fail;
    }

    gcry_mpi_release(retNonce);
    /* Extract server nonce */
    d += 16;
    gcry_mpi_scan(&serverNonce, GCRYMPI_FMT_USG, d, 16, NULL);
    free(rbuf.data);
    rbuf.data = NULL;
    /*
     * Round 3: Send an encrypted block containing the incremented server nonce,
     * the new password (256 bytes), and the old password (256 bytes)
     */
    gcry_mpi_add_ui(new_serverNonce, serverNonce, 1);
    int payload_len = 16 + 256 + 256; /* 528 bytes */

    if (afp_version >= 30) {
        ai_len = 2 + 2 + payload_len;
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx2_pw_fail;
        }

        *d++ = 0;
        *d++ = 0;
    } else {
        int pascal_len = 1 + strlen(username);
        int pad = (pascal_len & 1) ? 0 : 1;
        ai_len = pascal_len + pad + 2 + payload_len;
        d = ai = calloc(1, ai_len);

        if (ai == NULL) {
            goto dhx2_pw_fail;
        }

        d += copy_to_pascal(d, username) + 1;

        if ((long)d & 0x1) {
            ai_len--;
        } else {
            d++;
        }
    }

    /* Session ID (ID+1 from round 2 response) */
    *(unsigned short *)d = htons(ID);
    d += 2;
    /* Build plaintext: serverNonce+1(16) + new_pw(256) + old_pw(256) */
    char *plaintext_start = d;
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)d, 16, &len,
                   new_serverNonce);

    if (len < 16) {
        memmove(d + 16 - len, d, len);
        memset(d, 0, 16 - len);
    }

    d += 16;
    /* New password (256 bytes, null-padded) */
    memset(d, 0, 256);
    strlcpy(d, newpasswd, 256);
    d += 256;
    /* Old password (256 bytes, null-padded) */
    memset(d, 0, 256);
    strlcpy(d, passwd, 256);
    /* Encrypt with C2S IV */
    ctxerror = gcry_cipher_setiv(ctx, dhx_c2siv, sizeof(dhx_c2siv));

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_fail;
    }

    ctxerror = gcry_cipher_encrypt(ctx, plaintext_start, payload_len, NULL, 0);

    if (gcry_err_code(ctxerror) != GPG_ERR_NO_ERROR) {
        goto dhx2_pw_fail;
    }

    /* Send round 3 */
    ret = afp_changepassword(server, "DHX2", ai, ai_len, NULL);
    goto dhx2_pw_cleanup;
dhx2_pw_noctx_fail:
    ret = -1;
    goto dhx2_pw_noctx_cleanup;
dhx2_pw_fail:
    ret = -1;
dhx2_pw_cleanup:

    if (have_ctx) {
        gcry_cipher_close(ctx);
    }

dhx2_pw_noctx_cleanup:
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(Rb);
    gcry_mpi_release(Ma);
    gcry_mpi_release(Mb);
    gcry_mpi_release(K);
    gcry_mpi_release(clientNonce);
    gcry_mpi_release(new_clientNonce);
    gcry_mpi_release(serverNonce);
    gcry_mpi_release(new_serverNonce);
    free(Rb_binary);
    free(K_binary);
    free(K_hash);
    free(ai);
    free(rbuf.data);
    return ret;
}

#endif /* HAVE_LIBGCRYPT */

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

    if (u->do_server_passwd) {
        return u->do_server_passwd(server, username, oldpasswd, newpasswd);
    } else {
        return 0;
    }
}


