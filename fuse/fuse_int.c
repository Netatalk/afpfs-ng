/*

    fuse.c, FUSE interfaces for afpfs-ng

    Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
    Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>

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
#include <stdint.h>
#include <stdarg.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>

/* Extended attribute headers - platform dependent */
#if defined(HAVE_ATTR_XATTR_H)
#include <attr/xattr.h>
#elif defined(HAVE_SYS_XATTR_H)
#include <sys/xattr.h>
#elif defined(HAVE_SYS_EXTATTR_H)
#include <sys/extattr.h>
#endif

/* Define xattr constants if not provided by system headers */
#ifndef XATTR_CREATE
#define XATTR_CREATE 0x1
#endif
#ifndef XATTR_REPLACE
#define XATTR_REPLACE 0x2
#endif

/* If not defined by the build system, default to 0 (old API) */
#ifndef FUSE_NEW_API
#define FUSE_NEW_API 0
#endif

#include "dsi.h"
#include "afp_protocol.h"
#include "codepage.h"
#include "midlevel.h"
#include "fuse_error.h"

#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
/* Helper function to convert struct stat to struct fuse_darwin_attr on macOS */
static void stat_to_darwin_attr(const struct stat *st,
                                struct fuse_darwin_attr *attr)
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
    /* Set birth time (btimespec) to the creation time for macOS Finder display */
    attr->btimespec = st->st_birthtimespec;
    attr->size = st->st_size;
    attr->blocks = st->st_blocks;
    attr->blksize = st->st_blksize;
}

#endif

static int fuse_readlink(const char * path, char *buf, size_t size)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** readlink of %s", path);
    ret = ml_readlink(volume, path, buf, size);

    if (ret == -EFAULT) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Got some sort of internal error in afp_open for readlink");
    }

    return ret;
}

static int fuse_rmdir(const char *path)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** rmdir of %s", path);
    ret = ml_rmdir(volume, path);
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** rmdir returned %d", ret);
    return ret;
}

static int fuse_unlink(const char *path)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** unlink of %s", path);
    ret = ml_unlink(volume, path);
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** unlink returned %d", ret);
    return ret;
}

/* Extended attributes (AFP 3.2+) */
#ifdef __APPLE__
static int fuse_getxattr(const char *path, const char *name, char *value,
                         size_t size, uint32_t position)
#else
static int fuse_getxattr(const char *path, const char *name, char *value,
                         size_t size)
#endif
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
#ifdef __APPLE__

    /* AFP does not support positioned xattrs; ignore non-zero positions */
    if (position != 0) {
        return -EOPNOTSUPP;
    }

#endif
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** getxattr %s:%s (size=%zu)", path, name, size);
    ret = ml_getxattr(volume, path, name, value, size);
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** getxattr returned %d", ret);
    return ret;
}

#ifdef __APPLE__
static int fuse_setxattr(const char *path, const char *name,
                         const char *value, size_t size, int flags,
                         uint32_t position)
#else
static int fuse_setxattr(const char *path, const char *name,
                         const char *value, size_t size, int flags)
#endif
{
    int ml_flags = 0;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
#ifdef XATTR_CREATE

    if (flags & XATTR_CREATE) {
        ml_flags |= kXAttrCreate;
    }

#endif
#ifdef XATTR_REPLACE

    if (flags & XATTR_REPLACE) {
        ml_flags |= kXAttrREplace;
    }

#endif
#ifdef __APPLE__

    /* FIXME: macOS uses position for resource forks stored in xattr */
    if (position != 0) {
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "Positioned xattrs not supported (resource forks)");
        return -EOPNOTSUPP;
    }

#endif
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** setxattr %s:%s (size=%zu)", path, name, size);
    ret = ml_setxattr(volume, path, name, value, size, ml_flags);
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** setxattr returned %d", ret);
    return ret;
}

static int fuse_listxattr(const char *path, char *list, size_t size)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** listxattr %s (size=%zu)", path, size);
    ret = ml_listxattr(volume, path, list, size);
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** listxattr returned %d", ret);
    return ret;
}

static int fuse_removexattr(const char *path, const char *name)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** removexattr %s:%s", path, name);
    ret = ml_removexattr(volume, path, name);
    return ret;
}


/* Function signature differs by platform and FUSE version */
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
static int fuse_readdir_darwin(const char *path, void *buf,
                               fuse_darwin_fill_dir_t filler,
                               __attribute__((unused)) off_t offset,
                               __attribute__((unused)) struct fuse_file_info *fi,
                               __attribute__((unused)) enum fuse_readdir_flags flags)
#elif FUSE_USE_VERSION >= 30 && FUSE_NEW_API
/* Linux FUSE 3.10+ with fuse_readdir_flags */
static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        __attribute__((unused)) off_t offset,
                        __attribute__((unused)) struct fuse_file_info *fi,
                        __attribute__((unused)) enum fuse_readdir_flags flags)
#else
/* BSD FUSE 3.x and FUSE 2.x - older API without fuse_readdir_flags */
static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        __attribute__((unused)) off_t offset,
                        __attribute__((unused)) struct fuse_file_info *fi)
#endif
{
    struct afp_file_info * filebase = NULL, *p;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** readdir of %s", path);
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30 || (FUSE_USE_VERSION >= 30 && FUSE_NEW_API)
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
#else
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
#endif
    ret = ml_readdir(volume, path, &filebase);

    if (ret) {
        goto error;
    }

    for (p = filebase; p; p = p->next) {
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** readdir entry: %s", p->name);
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30 || (FUSE_USE_VERSION >= 30 && FUSE_NEW_API)
        filler(buf, p->name, NULL, 0, 0);
#else
        filler(buf, p->name, NULL, 0);
#endif
    }

    afp_ml_filebase_free(&filebase);
    return 0;
error:
    return ret;
}

static int fuse_mknod(const char *path, mode_t mode,
                      __attribute__((unused)) dev_t dev)
{
    int ret = 0;
    struct fuse_context * context = fuse_get_context();
    struct afp_volume * volume =
        (struct afp_volume *) context->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** mknod of %s", path);
    ret = ml_creat(volume, path, mode);
    return ret;
}

static int fuse_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    struct afp_file_info * fp;
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** create of %s with mode 0%o, flags 0x%x", path, mode, fi->flags);
    /* Create the file */
    ret = ml_creat(volume, path, mode);

    if (ret != 0 && ret != -EEXIST) {
        /* Fatal error other than file exists */
        return ret;
    }

    if (ret == -EEXIST) {
        /* File already exists - this can happen on retry after a transient failure.
         * Proceed to open the file; ml_open will handle O_TRUNC if needed. */
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** create: file exists, attempting to open anyway");
    }

    /* Open it. Strip O_CREAT and O_EXCL: ml_creat already created the file,
     * and sending a second FPCreateFile (hard create) for an existing file
     * causes Time Capsule to return kFPMiscErr on the subsequent FPWriteExt.
     * ml_open will handle O_TRUNC if present in flags. */
    ret = ml_open(volume, path, fi->flags & ~(O_CREAT | O_EXCL), &fp);

    if (ret == 0) {
        fi->fh = (unsigned long) fp;
        /* Bypass the kernel page cache so writes go directly to our daemon.
         * Without this, O_RDWR opens (used by macOS copyfile/Finder) buffer
         * writes in the UBC; those pages are never flushed before flush/release,
         * resulting in a 0-byte file on the server. */
        fi->direct_io = 1;
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** create succeeded, fh=%lu, forkid=%d",
                       fi->fh, fp->forkid);
    } else {
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** create open failed with ret=%d", ret);
    }

    return ret;
}

static int fuse_flush(const char *path, struct fuse_file_info *fi)
{
    struct afp_file_info *fp = (struct afp_file_info *) fi->fh;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret = 0;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** flush of %s", path);

    if (!fp) {
        return 0;
    }

    /* Flush the fork to ensure all writes are committed to the server */
    ret = afp_flushfork(volume, fp->forkid);

    if (ret != 0) {
        int eret;
        /* Map AFP errors to errno */
        switch (ret) {
        case kFPAccessDenied:
            eret = -EACCES;
            break;

        case kFPParamErr:
            eret = -EINVAL;
            break;

        default:
            eret = -EIO;
            break;
        }
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** flush returned %d (afp rc=%d)", eret, ret);
        return eret;
    }

    /* NOTE: We do NOT call afp_setforkparms here because it appears to
     * clear/reset the fork data even when setting to the current size.
     * afp_flushfork alone should be sufficient to commit the writes. */
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** flush returned 0");
    return 0;
}

static int fuse_release(const char * path, struct fuse_file_info * fi)
{
    struct afp_file_info * fp = (void *) fi->fh;
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** release of %s", path);
    ret = ml_close(volume, path, fp);
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** release returned %d", ret);

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
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** Opening path %s with flags 0x%x", path, flags);
    ret = ml_open(volume, path, flags, &fp);

    if (ret == 0) {
        fi->fh = (unsigned long) fp;
        /* Only bypass the UBC (direct_io) for writable opens.
         * For O_RDONLY, leaving direct_io=0 lets macOS use mmap() and
         * page-cache reads; setting it breaks Preview, QuickLook, and any
         * app that mmap()s a file — the VFS abandons the open immediately. */
        if (fi->flags & (O_WRONLY | O_RDWR)) {
            fi->direct_io = 1;
        }
    }

    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** open returned %d", ret);
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
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** write of %s from %llu for %llu bytes",
                   path, (unsigned long long) offset, (unsigned long long) size);
    ret = ml_write(volume, path, data, size, offset, fp,
                   context->uid, context->gid);
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** write returned %d", ret);
    return ret;
}


static int fuse_mkdir(const char * path, mode_t mode)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** mkdir of %s", path);
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
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** read of %s at offset %llu for %zu bytes",
                   path, (unsigned long long)offset, size);

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
                      __attribute__((unused)) struct fuse_file_info *fi)
#else
static int fuse_chown(const char * path, uid_t uid, gid_t gid)
#endif
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** chown %s to uid %d, gid %d",
                   path, (int)uid, (int)gid);
    ret = ml_chown(volume, path, uid, gid);

    if (ret == -ENOSYS) {
        log_for_client(NULL, AFPFSD, LOG_WARNING, "chown unsupported on this server");
    }

    return ret;
}

#if FUSE_NEW_API
static int fuse_truncate(const char * path, off_t offset,
                         struct fuse_file_info *fi)
{
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** truncate of %s to %lld, fi=%p, fh=%lu",
                   path, (long long)offset, (void*)fi, fi ? (unsigned long)fi->fh : 0UL);

    /* If we have an open file handle, use it directly instead of
     * opening/closing a new fork */
    if (fi && fi->fh) {
        struct afp_file_info *fp = (struct afp_file_info *) fi->fh;
        log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** truncate using open forkid %d",
                       fp->forkid);

        /* CRITICAL: Only call setforksize if we're actually changing the size.
         * Calling setforkparms on a fork that already has data can clear it! */
        if (fp->size != (uint64_t)offset) {
            ret = ml_setfork_size(volume, fp->forkid, 0, offset);

            if (ret == 0) {
                /* Update the cached size */
                fp->size = offset;
            }
        } else {
            ret = 0;
        }
    } else if (fi) {
        /* fi is provided but fh is not set yet (create in progress).
         * The file is being opened, so ll_open will handle O_TRUNC.
         * Don't call ml_truncate as it would close the fork being opened. */
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** truncate with fi but no fh - skipping (will be handled by open)");
        ret = 0;
    } else {
        log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** truncate calling ml_truncate");
        ret = ml_truncate(volume, path, offset);
    }

    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** truncate returning %d", ret);
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
                      __attribute__((unused)) struct fuse_file_info *fi)
#else
static int fuse_chmod(const char * path, mode_t mode)
#endif
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "** chmod %s", path);
    ret = ml_chmod(volume, path, mode);

    switch (ret) {
    case -EPERM:
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "You're not the owner of this file, cannot change permissions");
        break;

    case -ENOSYS:
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "chmod unsupported or this mode is not possible with this server");
        break;

    case -EFAULT:
        log_for_client(NULL, AFPFSD, LOG_ERR,
                       "We don't support these permission bits on this server");
        ret = 0;
        break;
    }

    return ret;
}

#if FUSE_USE_VERSION >= 30
#if FUSE_NEW_API
static int fuse_utimens(const char *path, const struct timespec tv[2],
                        __attribute__((unused)) struct fuse_file_info *fi)
#else
static int fuse_utimens(const char *path, const struct timespec tv[2])
#endif
{
    int ret = 0;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "** utimens");
    struct utimbuf timebuf;

    if (!tv) {
        /* NULL tv means set both timestamps to current time */
        time_t now = time(NULL);
        timebuf.actime = now;
        timebuf.modtime = now;
        ret = ml_utime(volume, path, &timebuf);
        return ret;
    }

    /*
     * AFP only supports modification time, so we only need to check
     * tv[1] (mtime).  If mtime is UTIME_OMIT, there is nothing to do.
     */
    if (tv[1].tv_nsec == UTIME_OMIT) {
        return 0;
    }

    if (tv[1].tv_nsec == UTIME_NOW) {
        timebuf.modtime = time(NULL);
    } else {
        timebuf.modtime = tv[1].tv_sec;
    }

    /* unused by AFP, just initialize */
    timebuf.actime = timebuf.modtime;
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
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "** utime");
    ret = ml_utime(volume, path, timebuf);
    return ret;
}

#endif

static void afp_destroy(__attribute__((unused)) void * ignore)
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;

    if (!volume || !volume->server) {
        return;
    }

    if (volume->mounted == AFP_VOLUME_UNMOUNTED) {
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "Volume %s already unmounted", volume->volume_name_printable);
        return;
    }

    /* If volume is currently unmounting, afp_destroy() was called from within
     * fuse_unmount() (during the FUSE shutdown sequence). In this case, we
     * must NOT call afp_unmount_volume() again as it would create a nested
     * unmount. */
    if (volume->mounted == AFP_VOLUME_UNMOUNTING) {
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "Volume %s is already unmounting - skipping destroy callback",
                       volume->volume_name_printable);
        return;
    }

    /* afp_destroy() is being called for an externally-initiated unmount
     * (e.g., via umount command). The kernel has unmounted the filesystem,
     * so we need to do AFP-side cleanup only. */
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "FUSE destroy callback - external unmount of %s",
                   volume->volume_name_printable);
    volume->priv = NULL;
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
                       "Got some sort of internal error in when creating symlink");
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
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** rename %s -> %s", path_from, path_to);
    ret = ml_rename(volume, path_from, path_to);
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** rename returned %d", ret);
    return ret;
}

#else
static int fuse_rename(const char * path_from, const char * path_to)
{
    int ret;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** rename %s -> %s", path_from, path_to);
    ret = ml_rename(volume, path_from, path_to);
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** rename returned %d", ret);
    return ret;
}

#endif

#ifdef __APPLE__
#if FUSE_USE_VERSION >= 30
static int fuse_statfs(const char *path, struct statfs *stat)
#else
static int fuse_statfs(const char *path, struct statvfs *stat)
#endif
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


#if defined(__APPLE__) && FUSE_USE_VERSION >= 30

/* FUSE_SET_ATTR_* bitmask constants (from fuse3/fuse_lowlevel.h) */
#ifndef FUSE_SET_ATTR_MODE
#define FUSE_SET_ATTR_MODE      (1 << 0)
#define FUSE_SET_ATTR_UID       (1 << 1)
#define FUSE_SET_ATTR_GID       (1 << 2)
#define FUSE_SET_ATTR_SIZE      (1 << 3)
#define FUSE_SET_ATTR_ATIME     (1 << 4)
#define FUSE_SET_ATTR_MTIME     (1 << 5)
#define FUSE_SET_ATTR_ATIME_NOW (1 << 7)
#define FUSE_SET_ATTR_MTIME_NOW (1 << 8)
#define FUSE_SET_ATTR_BTIME     (1 << 28)
#endif

/* Darwin-specific combined setattr callback.  macFUSE with FUSE_USE_VERSION >= 30
 * routes ALL setattrlist() calls here instead of to the individual chmod/chown/
 * truncate/utimens callbacks.  Without this, setattrlist returns ENOSYS and
 * macOS copyfile() aborts the copy before writing any data. */
static int fuse_setattr(const char *path, struct fuse_darwin_attr *attr,
                        int to_set, struct fuse_file_info *fi)
{
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret = 0;
    log_for_client(NULL, AFPFSD, LOG_DEBUG,
                   "*** setattr \"%s\" to_set=0x%x", path, to_set);

    if (to_set & FUSE_SET_ATTR_MODE) {
        ret = ml_chmod(volume, path, attr->mode);
        /* Ignore ENOSYS/EPERM: server may not support Unix privs */
        if (ret == -ENOSYS || ret == -EPERM || ret == -EACCES) {
            ret = 0;
        } else if (ret < 0) {
            log_for_client(NULL, AFPFSD, LOG_WARNING,
                           "*** setattr chmod \"%s\" failed: %d", path, ret);
            return ret;
        }
    }

    if (to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
        ret = ml_chown(volume, path, attr->uid, attr->gid);
        if (ret == -ENOSYS || ret == -EPERM || ret == -EACCES) {
            ret = 0;
        } else if (ret < 0) {
            log_for_client(NULL, AFPFSD, LOG_WARNING,
                           "*** setattr chown \"%s\" failed: %d", path, ret);
            return ret;
        }
    }

    if (to_set & FUSE_SET_ATTR_SIZE) {
        if (fi && fi->fh) {
            struct afp_file_info *fp = (struct afp_file_info *) fi->fh;
            if (fp->size != (uint64_t)attr->size) {
                ret = ml_setfork_size(volume, fp->forkid, 0, attr->size);
                if (ret == 0)
                    fp->size = attr->size;
            }
        } else {
            ret = ml_truncate(volume, path, attr->size);
        }
        if (ret < 0) {
            log_for_client(NULL, AFPFSD, LOG_WARNING,
                           "*** setattr truncate \"%s\" failed: %d", path, ret);
            return ret;
        }
    }

    if (to_set & (FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_MTIME_NOW)) {
        struct utimbuf timebuf;
        timebuf.modtime = (to_set & FUSE_SET_ATTR_MTIME_NOW)
                          ? time(NULL) : (time_t)attr->mtimespec.tv_sec;
        timebuf.actime  = timebuf.modtime;
        ret = ml_utime(volume, path, &timebuf);
        /* Treat timestamp-setting failures as non-fatal on AFP volumes:
         * kFPObjectNotFound (ENOENT) can occur transiently after catalog
         * updates, and EACCES may indicate a read-only fork; neither
         * should cause macOS to abort an otherwise-successful safe-save. */
        if (ret == -ENOSYS || ret == -EPERM || ret == -ENOENT || ret == -EACCES) {
            if (ret != 0)
                log_for_client(NULL, AFPFSD, LOG_DEBUG,
                               "*** setattr utime \"%s\" ignored: %d", path, ret);
            ret = 0;
        } else if (ret < 0) {
            log_for_client(NULL, AFPFSD, LOG_WARNING,
                           "*** setattr utime \"%s\" failed: %d", path, ret);
            return ret;
        }
    }

    /* Birth time / backup time: AFP has no API for setting these */
    return 0;
}

static int fuse_getattr_darwin(const char *path, struct fuse_darwin_attr *attr,
                               __attribute__((unused)) struct fuse_file_info *fi)
{
    char *c;
    struct stat stbuf;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** getattr of \"%s\"", path);

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
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** getattr \"%s\" -> mode=0%o uid=%d gid=%d size=%lld ino=%llu",
                       path, stbuf.st_mode, stbuf.st_uid, stbuf.st_gid,
                       (long long)stbuf.st_size, (unsigned long long)stbuf.st_ino);
    } else {
        log_for_client(NULL, AFPFSD, LOG_DEBUG,
                       "*** getattr \"%s\" -> error %d", path, ret);
    }

    return ret;
}
#else
#if FUSE_NEW_API
static int fuse_getattr(const char *path, struct stat *stbuf,
                        __attribute__((unused)) struct fuse_file_info *fi)
#else
static int fuse_getattr(const char *path, struct stat *stbuf)
#endif
{
    char *c;
    struct afp_volume * volume =
        (struct afp_volume *)
        ((struct fuse_context *)(fuse_get_context()))->private_data;
    int ret;
    log_for_client(NULL, AFPFSD, LOG_DEBUG, "*** getattr of \"%s\"", path);

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


#if FUSE_NEW_API
static void *afp_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void) conn;
    (void) cfg;
    struct afp_volume * vol = (struct afp_volume *)
                              ((struct fuse_context *)(fuse_get_context()))->private_data;
    struct fuse_context *ctx = fuse_get_context();

    if (ctx && ctx->fuse) {
        vol->priv = ctx->fuse;
    } else {
        vol->priv = NULL;
        log_for_client(NULL, AFPFSD, LOG_WARNING,
                       "FUSE handle not available in context for %s",
                       vol->volume_name_printable);
    }

    /* Trigger the daemon that we've started */
    vol->mounted = 1;
    pthread_cond_signal(&vol->startup_condition_cond);
    return (void *) vol;
}

#else
static void *afp_init(__attribute__((unused)) struct fuse_conn_info * o)
{
    struct afp_volume * vol = (struct afp_volume *)
                              ((struct fuse_context *)(fuse_get_context()))->private_data;
    vol->priv = (void *)((struct fuse_context *)(fuse_get_context()))->fuse;

    /* Trigger the daemon that we've started */
    if (vol->priv) {
        vol->mounted = 1;
    }

    pthread_cond_signal(&vol->startup_condition_cond);
    return (void *) vol;
}

#endif

#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
static int fuse_chflags(__attribute__((unused)) const char *path,
                        __attribute__((unused)) struct fuse_file_info *fi,
                        __attribute__((unused)) unsigned int flags)
{
    /* AFP doesn't support BSD file flags, so we just return success
     * to avoid "Function not implemented" errors when using mv/cp */
    return 0;
}

#endif

static struct fuse_operations afp_oper = {
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
    .getattr    = fuse_getattr_darwin,
    .setattr    = fuse_setattr,
    .readdir    = fuse_readdir_darwin,
    .chflags    = fuse_chflags,
#else
    .getattr    = fuse_getattr,
    .readdir    = fuse_readdir,
#endif
    .open       = fuse_open,
    .read       = fuse_read,
    .mkdir      = fuse_mkdir,
    .readlink   = fuse_readlink,
    .rmdir      = fuse_rmdir,
    .unlink     = fuse_unlink,
    .mknod      = fuse_mknod,
    .create     = fuse_create,
    .write      = fuse_write,
    .flush      = fuse_flush,
    .release    = fuse_release,
    .getxattr   = fuse_getxattr,
    .setxattr   = fuse_setxattr,
    .listxattr  = fuse_listxattr,
    .removexattr = fuse_removexattr,
    .chmod      = fuse_chmod,
    .symlink    = fuse_symlink,
    .chown      = fuse_chown,
    .truncate   = fuse_truncate,
    .rename     = fuse_rename,
#if FUSE_USE_VERSION >= 30
    .utimens    = fuse_utimens,
#else
    .utime      = fuse_utime,
#endif
    .destroy    = afp_destroy,
    .init       = afp_init,
    .statfs     = fuse_statfs,
};


int afp_register_fuse(int fuseargc, char *fuseargv[], struct afp_volume * vol)
{
    int ret;
    struct fuse_operations oper = afp_oper;

    /* Only register xattr ops if the server supports extended attributes.
     * If unregistered (NULL), FUSE returns ENOSYS and macOS uses AFP's
     * native FinderInfo/resource fork mechanism instead of falling back
     * to ._AppleDouble sidecar files. */
    if (!(vol->attributes & kSupportsExtAttrs)) {
        oper.getxattr    = NULL;
        oper.setxattr    = NULL;
        oper.listxattr   = NULL;
        oper.removexattr = NULL;
    }

    fuse_capture_stderr_start();
    ret = fuse_main(fuseargc, fuseargv, &oper, (void *) vol);
    return ret;
}
