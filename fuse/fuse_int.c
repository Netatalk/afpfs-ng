/*

    fuse.c, FUSE interfaces for afpfs-ng

    Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>

    Heavily modifed from the example code provided by:
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#define HAVE_ARCH_STRUCT_FLOCK

#include "afp.h"

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>

/* Detect if we should use new FUSE 3.10+ API with extra fuse_file_info parameters
 * BSD systems (FreeBSD, OpenBSD, NetBSD, DragonFly) use older FUSE 3 API */
#if FUSE_USE_VERSION >= 30 && !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) && !defined(__DragonFly__)
#define FUSE_NEW_API 1
#else
#define FUSE_NEW_API 0
#endif
#include <stdarg.h>

#include "dsi.h"
#include "afp_protocol.h"
#include "codepage.h"
#include "midlevel.h"
#include "../lib/lowlevel.h"
#include "fuse_error.h"

/* enable full debugging: */
#ifdef DEBUG
#define LOG_FUSE_EVENTS
#endif

#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
/* Helper function to convert struct stat to struct fuse_darwin_attr on macOS */
static void stat_to_darwin_attr(const struct stat *st, struct fuse_darwin_attr *attr)
{
    memset(attr, 0, sizeof(struct fuse_darwin_attr));
    attr->ino = st->st_ino;
    attr->mode = st->st_mode;
    attr->nlink = st->st_nlink;
    attr->uid = st->st_uid;
    attr->gid = st->st_gid;
    attr->rdev = st->st_rdev;
    attr->atimespec = st->st_atimespec;
    attr->mtimespec = st->st_mtimespec;
    attr->ctimespec = st->st_ctimespec;
    attr->size = st->st_size;
    attr->blocks = st->st_blocks;
    attr->blksize = st->st_blksize;
}
#endif

void log_fuse_event(__attribute__((unused)) enum loglevels loglevel,
                    __attribute__((unused)) int logtype,
                    __attribute__((unused)) char *format, ...)
{
#ifdef LOG_FUSE_EVENTS
    va_list ap;
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
#endif
}


static int fuse_readlink(const char * path, char *buf, size_t size)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** readlink of %s\n", path);
    ret = ml_readlink(volume, path, buf, size);

    if (ret == -EFAULT) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Got some sort of internal error in afp_open for readlink\n");
    }

    return ret;
}

static int fuse_rmdir(const char *path)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** rmdir of %s\n", path);
    ret = ml_rmdir(volume, path);
    return ret;
}

static int fuse_unlink(const char *path)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** unlink of %s\n", path);
    ret = ml_unlink(volume, path);
    return ret;
}


#ifdef __APPLE__
#if FUSE_USE_VERSION >= 30
static int fuse_readdir_darwin(const char *path, void *buf, fuse_darwin_fill_dir_t filler,
                               off_t offset, struct fuse_file_info *fi,
                               enum fuse_readdir_flags flags)
{
    (void) offset;
    (void) fi;
    (void) flags;
    struct afp_file_info * filebase = NULL, *p;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** readdir of %s\n", path);
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    ret = ml_readdir(volume, path, &filebase);

    if (ret) {
        goto error;
    }

    for (p = filebase; p; p = p->next) {
        filler(buf, p->name, NULL, 0, 0);
    }

    afp_ml_filebase_free(&filebase);
    return 0;
error:
    return ret;
}
#endif
#else
#if FUSE_USE_VERSION >= 30
static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;
    struct afp_file_info * filebase = NULL, *p;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** readdir of %s\n", path);
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    ret = ml_readdir(volume, path, &filebase);

    if (ret) {
        goto error;
    }

    for (p = filebase; p; p = p->next) {
        filler(buf, p->name, NULL, 0);
    }

    afp_ml_filebase_free(&filebase);
    return 0;
error:
    return ret;
}
#else
static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;
    struct afp_file_info * filebase = NULL, *p;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** readdir of %s\n", path);
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    ret = ml_readdir(volume, path, &filebase);

    if (ret) {
        goto error;
    }

    for (p = filebase; p; p = p->next) {
        filler(buf, p->name, NULL, 0);
    }

    afp_ml_filebase_free(&filebase);
    return 0;
error:
    return ret;
}
#endif
#endif

static int fuse_mknod(const char *path, mode_t mode,
                      __attribute__((unused)) dev_t dev)
{
    int ret = 0;
    struct fuse_context * context = fuse_get_context();
    struct afp_volume * volume =
        (struct afp_volume *) context->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** mknod of %s\n", path);
    ret = ml_creat(volume, path, mode);
    return ret;
}


static int fuse_release(const char * path, struct fuse_file_info * fi)
{
    struct afp_file_info * fp = (void *) fi->fh;
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** release of %s\n", path);
    ret = ml_close(volume, path, fp);

    if (ret < 0) {
        goto error;
    }

    return ret;
error:
    free((void *) fi->fh);
    return ret;
}

static int fuse_open(const char *path, struct fuse_file_info *fi)
{
    struct afp_file_info * fp ;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int flags = fi->flags;
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "*** Opening path %s with flags 0x%x\n", path, flags);
    ret = ml_open(volume, path, flags, &fp);

    if (ret == 0) {
        fi->fh = (unsigned long) fp;
    }

    return ret;
}


static int fuse_write(const char * path, const char *data,
                      size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
    struct afp_file_info *fp = (struct afp_file_info *) fi->fh;
    int ret;
    struct fuse_context * context = fuse_get_context();
    struct afp_volume * volume = (void *) context->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "*** write of %s from %llu for %llu bytes\n",
                   path, (unsigned long long) offset, (unsigned long long) size);
    ret = ml_write(volume, path, data, size, offset, fp,
                   context->uid, context->gid);
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "*** write returned %d\n", ret);
    return ret;
}


static int fuse_mkdir(const char * path, mode_t mode)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** mkdir of %s\n", path);
    ret = ml_mkdir(volume, path, mode);
    return ret;
}
static int fuse_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{
    struct afp_file_info * fp;
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int eof;
    size_t amount_read = 0;

    if (!fi || !fi->fh) {
        return -EBADF;
    }

    fp = (void *) fi->fh;

    while (1) {
        ret = ml_read(volume, path, buf + amount_read, size, offset, fp, &eof);

        if (ret < 0) {
            goto error;
        }

        amount_read += ret;

        if (eof) {
            goto out;
        }

        size -= ret;

        if (size == 0) {
            goto out;
        }

        offset += ret;
    }

out:
    return amount_read;
error:
    return ret;
}

#if FUSE_NEW_API
static int fuse_chown(const char * path, uid_t uid, gid_t gid,
                      struct fuse_file_info *fi)
{
    (void) fi;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "** chown\n");
    ret = ml_chown(volume, path, uid, gid);

    if (ret == -ENOSYS) {
        log_for_client(NULL, AFPFSD, LOG_WARNING, "chown unsupported\n");
    }

    return ret;
}
#else
static int fuse_chown(const char * path, uid_t uid, gid_t gid)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG, "** chown\n");
    ret = ml_chown(volume, path, uid, gid);

    if (ret == -ENOSYS) {
        log_for_client(NULL, AFPFSD, LOG_WARNING, "chown unsupported\n");
    }

    return ret;
}
#endif

#if FUSE_NEW_API
static int fuse_truncate(const char * path, off_t offset,
                         struct fuse_file_info *fi)
{
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    
    /* If we have an open file handle, use it directly instead of
     * opening/closing a new fork */
    if (fi && fi->fh) {
        struct afp_file_info *fp = (struct afp_file_info *) fi->fh;
        ret = ll_setfork_size(volume, fp->forkid, 0, offset);
        if (ret == 0) {
            /* Update the cached size */
            fp->size = offset;
        }
        ret = -ret;  /* ll_setfork_size returns positive errno */
    } else {
        ret = ml_truncate(volume, path, offset);
    }
    
    return ret;
}
#else
static int fuse_truncate(const char * path, off_t offset)
{
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    ret = ml_truncate(volume, path, offset);
    return ret;
}
#endif


#if FUSE_NEW_API
static int fuse_chmod(const char * path, mode_t mode,
                      struct fuse_file_info *fi)
{
    (void) fi;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "** chmod %s\n", path);
    ret = ml_chmod(volume, path, mode);

    switch (ret) {
    case -EPERM:
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "You're not the owner of this file.\n");
        break;

    case -ENOSYS:
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "chmod unsupported or this mode is not possible with this server\n");
        break;

    case -EFAULT:
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "I was trying to change permissions but you're setting "
                       "some mode bits that we don't support.\n"
                       "Are you possibly mounting from a netatalk server "
                       "with \"unix priv = no\" in afp.conf?\n"
                       "I'm marking this volume as broken for 'extended' chmod modes.\n"
                       "Allowed bits are: %o\n", AFP_CHMOD_ALLOWED_BITS_22);
        ret = 0;
        break;
    }

    return ret;
}
#else
static int fuse_chmod(const char * path, mode_t mode)
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "** chmod %s\n", path);
    ret = ml_chmod(volume, path, mode);

    switch (ret) {
    case -EPERM:
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "You're not the owner of this file.\n");
        break;

    case -ENOSYS:
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "chmod unsupported or this mode is not possible with this server\n");
        break;

    case -EFAULT:
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "I was trying to change permissions but you're setting "
                       "some mode bits that we don't support.\n"
                       "Are you possibly mounting from a netatalk server "
                       "with \"unix priv = no\" in afp.conf?\n"
                       "I'm marking this volume as broken for 'extended' chmod modes.\n"
                       "Allowed bits are: %o\n", AFP_CHMOD_ALLOWED_BITS_22);
        ret = 0; /* Return anyway */
        break;
    }

    return ret;
}
#endif

#if FUSE_NEW_API
static int fuse_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi)
{
    (void) fi;
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "** utimens\n");
    /* Convert timespec to utimbuf for ml_utime */
    struct utimbuf timebuf;

    if (tv) {
        timebuf.actime = tv[0].tv_sec;
        timebuf.modtime = tv[1].tv_sec;
    } else {
        time_t now = time(NULL);
        timebuf.actime = now;
        timebuf.modtime = now;
    }

    ret = ml_utime(volume, path, &timebuf);
    return ret;
}
#elif FUSE_USE_VERSION >= 30
static int fuse_utimens(const char *path, const struct timespec tv[2])
{
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "** utimens\n");
    /* Convert timespec to utimbuf for ml_utime */
    struct utimbuf timebuf;

    if (tv) {
        timebuf.actime = tv[0].tv_sec;
        timebuf.modtime = tv[1].tv_sec;
    } else {
        time_t now = time(NULL);
        timebuf.actime = now;
        timebuf.modtime = now;
    }

    ret = ml_utime(volume, path, &timebuf);
    return ret;
}
#else
static int fuse_utime(const char * path, struct utimbuf * timebuf)
{
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_fuse_event(AFPFSD, LOG_DEBUG,
                   "** utime\n");
    ret = ml_utime(volume, path, timebuf);
    return ret;
}
#endif

static void afp_destroy(__attribute__((unused)) void * ignore)
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;

    if (volume->mounted == AFP_VOLUME_UNMOUNTED) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Skipping unmounting of the volume %s\n", volume->volume_name_printable);
        return;
    }

    if ((!volume) || (!volume->server)) {
        return;
    }

    /* We're just ignoring the results since there's nothing we could
       do with them anyway.  */
    afp_unmount_volume(volume);
}

static int fuse_symlink(const char * path1, const char * path2)
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    ret = ml_symlink(volume, path1, path2);

    if ((ret == -EFAULT) || (ret == -ENOSYS)) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Got some sort of internal error in when creating symlink\n");
    }

    return ret;
}

#if FUSE_NEW_API
static int fuse_rename(const char * path_from, const char * path_to,
                       unsigned int flags)
{
    (void) flags;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    ret = ml_rename(volume, path_from, path_to);
    return ret;
}
#else
static int fuse_rename(const char * path_from, const char * path_to)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    ret = ml_rename(volume, path_from, path_to);
    return ret;
}
#endif

#ifdef __APPLE__
static int fuse_statfs(const char *path, struct statfs *stat)
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    struct statvfs vfsstat;
    ret = ml_statfs(volume, path, &vfsstat);
    if (ret == 0) {
        /* Convert statvfs to statfs for macOS */
        stat->f_bsize = vfsstat.f_bsize;
        stat->f_blocks = vfsstat.f_blocks;
        stat->f_bfree = vfsstat.f_bfree;
        stat->f_bavail = vfsstat.f_bavail;
        stat->f_files = vfsstat.f_files;
        stat->f_ffree = vfsstat.f_ffree;
    }
    return ret;
}
#else
static int fuse_statfs(const char *path, struct statvfs *stat)
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    ret = ml_statfs(volume, path, stat);
    return ret;
}
#endif


#ifdef __APPLE__
#if FUSE_USE_VERSION >= 30
static int fuse_getattr_darwin(const char *path, struct fuse_darwin_attr *attr,
                               struct fuse_file_info *fi)
{
    (void) fi;
    char *c;
    struct stat stbuf;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** getattr of \"%s\"\n", path);

    /* Oddly, we sometimes get <dir1>/<dir2>/(null) for the path */

    if (!path) {
        return -EIO;
    }

    if ((c = strstr(path, "(null)"))) {
        /* We should fix this to make sure it is at the end */
        if (c > path) {
            *(c - 1) = '\0';
        }
    }

    ret = ml_getattr(volume, path, &stbuf);
    if (ret == 0) {
        stat_to_darwin_attr(&stbuf, attr);
    }
    return ret;
}
#endif
#else
#if FUSE_NEW_API
static int fuse_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi)
{
    (void) fi;
    char *c;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** getattr of \"%s\"\n", path);

    /* Oddly, we sometimes get <dir1>/<dir2>/(null) for the path */

    if (!path) {
        return -EIO;
    }

    if ((c = strstr(path, "(null)"))) {
        /* We should fix this to make sure it is at the end */
        if (c > path) {
            *(c - 1) = '\0';
        }
    }

    ret = ml_getattr(volume, path, stbuf);
    return ret;
}
#else
static int fuse_getattr(const char *path, struct stat *stbuf)
{
    char *c;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_fuse_event(AFPFSD, LOG_DEBUG, "*** getattr of \"%s\"\n", path);

    /* Oddly, we sometimes get <dir1>/<dir2>/(null) for the path */

    if (!path) {
        return -EIO;
    }

    if ((c = strstr(path, "(null)"))) {
        /* We should fix this to make sure it is at the end */
        if (c > path) {
            *(c - 1) = '\0';
        }
    }

    ret = ml_getattr(volume, path, stbuf);
    return ret;
}
#endif
#endif


static struct afp_volume *global_volume;

#if FUSE_NEW_API
static void *afp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void) conn;
    (void) cfg;
    struct afp_volume * vol = global_volume;
    
    /* In FUSE 3 on some platforms, the fuse field might not be available
     * Try to get it if available, otherwise use NULL */
#ifdef __APPLE__
    /* macFUSE might not have the fuse field in context */
    vol->priv = NULL;
#else
    /* Linux FUSE 3 might still have it */
    struct fuse_context *ctx = fuse_get_context();
    if (ctx) {
        vol->priv = ctx->fuse;
    } else {
        vol->priv = NULL;
    }
#endif

    /* Trigger the daemon that we've started */
    vol->mounted = 1;
    pthread_cond_signal(&vol->startup_condition_cond);
    return (void *) vol;
}
#else
static void *afp_init(__attribute__((unused)) struct fuse_conn_info * o)
{
    struct afp_volume * vol = global_volume;
    vol->priv = (void *)((struct fuse_context *)(fuse_get_context()))->fuse;

    /* Trigger the daemon that we've started */
    if (vol->priv) {
        vol->mounted = 1;
    }

    pthread_cond_signal(&vol->startup_condition_cond);
    return (void *) vol;
}
#endif


static struct fuse_operations afp_oper = {
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
    .getattr	= fuse_getattr_darwin,
    .open	= fuse_open,
    .read	= fuse_read,
    .readdir	= fuse_readdir_darwin,
#else
    .getattr	= fuse_getattr,
    .open	= fuse_open,
    .read	= fuse_read,
    .readdir	= fuse_readdir,
#endif
    .mkdir      = fuse_mkdir,
    .readlink = fuse_readlink,
    .rmdir	= fuse_rmdir,
    .unlink = fuse_unlink,
    .mknod  = fuse_mknod,
    .write = fuse_write,
    .release = fuse_release,
    .chmod = fuse_chmod,
    .symlink = fuse_symlink,
    .chown = fuse_chown,
    .truncate = fuse_truncate,
    .rename = fuse_rename,
#if FUSE_NEW_API
    .utimens = fuse_utimens,
#elif FUSE_USE_VERSION >= 30
    .utimens = fuse_utimens,
#else
    .utime = fuse_utime,
#endif
    .destroy = afp_destroy,
    .init = afp_init,
    .statfs = fuse_statfs,
};


int afp_register_fuse(int fuseargc, char *fuseargv[], struct afp_volume * vol)
{
    int ret;
    global_volume = vol;
    fuse_capture_stderr_start();
    ret = fuse_main(fuseargc, fuseargv, &afp_oper, (void *) vol);
    return ret;
}
