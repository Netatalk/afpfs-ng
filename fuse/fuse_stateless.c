/*
 * fuse_stateless.c - Stateless FUSE operations for afpfs-ng
 *
 * Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>
 * Copyright (C) 2025 Daniel Markstedt <daniel@mindani.net>
 *
 * This is a thin FUSE shim that translates FUSE callbacks to stateless
 * IPC calls via libafpsl. All AFP protocol state lives in the afpfsd daemon.
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define HAVE_ARCH_STRUCT_FLOCK

#include "afp.h"
#include "afpsl.h"
#include "afpfsd.h"

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/statvfs.h>
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

#include "libafpclient.h"
#include "fuse_error.h"

/*
 * File handle structure for stateless operations.
 * This is much simpler than the stateful version - we just store
 * opaque IDs from the daemon.
 */
struct stateless_file_handle {
    unsigned int fileid;        /* Opaque file ID from daemon */
    volumeid_t volumeid;        /* Volume reference */
};

/* Global volume ID for this mount (set during init) */
static volumeid_t mount_volumeid;

/*
 * Convert IPC result codes to errno values
 */
static int sl_result_to_errno(int result)
{
    switch (result) {
    case AFP_SERVER_RESULT_OKAY:
        return 0;
    case AFP_SERVER_RESULT_ENOENT:
        return -ENOENT;
    case AFP_SERVER_RESULT_ERROR:
        return -EIO;
    case AFP_SERVER_RESULT_NOTCONNECTED:
    case AFP_SERVER_RESULT_NOTATTACHED:
        return -ENOTCONN;
    case AFP_SERVER_RESULT_NOAUTHENT:
        return -EACCES;
    case AFP_SERVER_RESULT_NOVOLUME:
        return -ENOENT;
    case AFP_SERVER_RESULT_NOTSUPPORTED:
        return -ENOTSUP;
    default:
        return -EIO;
    }
}

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
    attr->btimespec = st->st_birthtimespec;
    attr->size = st->st_size;
    attr->blocks = st->st_blocks;
    attr->blksize = st->st_blksize;
}
#endif

/*
 * FUSE getattr - get file attributes
 */
#ifdef __APPLE__
#if FUSE_USE_VERSION >= 30
static int sl_getattr_darwin(const char *path, struct fuse_darwin_attr *attr,
                             struct fuse_file_info *fi)
{
    (void) fi;
    struct stat stbuf;
    int ret;

    if (!path) {
        return -EIO;
    }

    ret = afp_sl_stat(&mount_volumeid, path, &stbuf);
    if (ret == AFP_SERVER_RESULT_OKAY) {
        stat_to_darwin_attr(&stbuf, attr);
        return 0;
    }

    return sl_result_to_errno(ret);
}
#endif
#else
#if FUSE_NEW_API
static int sl_getattr(const char *path, struct stat *stbuf,
                      struct fuse_file_info *fi)
{
    (void) fi;
#else
static int sl_getattr(const char *path, struct stat *stbuf)
{
#endif
    int ret;

    if (!path) {
        return -EIO;
    }

    ret = afp_sl_stat(&mount_volumeid, path, stbuf);
    if (ret == AFP_SERVER_RESULT_OKAY) {
        return 0;
    }

    return sl_result_to_errno(ret);
}
#endif

/*
 * FUSE readdir - read directory contents
 */
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
static int sl_readdir_darwin(const char *path, void *buf,
                             fuse_darwin_fill_dir_t filler,
                             off_t offset, struct fuse_file_info *fi,
                             enum fuse_readdir_flags flags)
#elif FUSE_USE_VERSION >= 30 && FUSE_NEW_API
static int sl_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags)
#else
static int sl_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi)
#endif
{
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30 || (FUSE_USE_VERSION >= 30 && FUSE_NEW_API)
    (void) offset;
    (void) fi;
    (void) flags;
#else
    (void) offset;
    (void) fi;
#endif
    struct afp_file_info_basic *entries = NULL;
    unsigned int numfiles = 0;
    int eod = 0;
    int ret;
    int start = 0;
    const int count = 100;  /* Fetch in batches */

    /* Add standard entries */
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30 || (FUSE_USE_VERSION >= 30 && FUSE_NEW_API)
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
#else
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
#endif

    /* Fetch directory entries in batches until end of directory */
    while (!eod) {
        ret = afp_sl_readdir(&mount_volumeid, path, start, count,
                             &numfiles, &entries, &eod);

        if (ret != AFP_SERVER_RESULT_OKAY) {
            return sl_result_to_errno(ret);
        }

        if (entries && numfiles > 0) {
            for (unsigned int i = 0; i < numfiles; i++) {
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30 || (FUSE_USE_VERSION >= 30 && FUSE_NEW_API)
                filler(buf, entries[i].name, NULL, 0, 0);
#else
                filler(buf, entries[i].name, NULL, 0);
#endif
            }
            free(entries);
            entries = NULL;
        }

        start += numfiles;
    }

    return 0;
}

/*
 * FUSE open - open a file
 */
static int sl_open(const char *path, struct fuse_file_info *fi)
{
    struct stateless_file_handle *fh;
    unsigned int fileid;
    int ret;

    ret = afp_sl_open(&mount_volumeid, path, fi->flags, &fileid);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }

    fh = malloc(sizeof(struct stateless_file_handle));
    if (!fh) {
        afp_sl_close(&mount_volumeid, fileid);
        return -ENOMEM;
    }

    fh->fileid = fileid;
    memcpy(&fh->volumeid, &mount_volumeid, sizeof(volumeid_t));
    fi->fh = (uint64_t)(uintptr_t)fh;

    return 0;
}

/*
 * FUSE create - create and open a new file
 */
static int sl_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    struct stateless_file_handle *fh;
    unsigned int fileid;
    int ret;

    ret = afp_sl_create(&mount_volumeid, path, fi->flags, mode, &fileid);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }

    fh = malloc(sizeof(struct stateless_file_handle));
    if (!fh) {
        afp_sl_close(&mount_volumeid, fileid);
        return -ENOMEM;
    }

    fh->fileid = fileid;
    memcpy(&fh->volumeid, &mount_volumeid, sizeof(volumeid_t));
    fi->fh = (uint64_t)(uintptr_t)fh;

    return 0;
}

/*
 * FUSE read - read from a file
 */
static int sl_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi)
{
    (void) path;
    struct stateless_file_handle *fh;
    int eof = 0;
    size_t total_read = 0;
    int ret;

    if (!fi || !fi->fh) {
        return -EBADF;
    }

    fh = (struct stateless_file_handle *)(uintptr_t)fi->fh;

    /* Read in a loop until we have all data or hit EOF */
    while (total_read < size && !eof) {
        unsigned int chunk_received = 0;
        unsigned int chunk_size = size - total_read;

        /* Limit chunk size to 64KB to match AFP max packet size */
        if (chunk_size > 65536) {
            chunk_size = 65536;
        }

        ret = afp_sl_read(&fh->volumeid, fh->fileid, 0,
                          offset + total_read, chunk_size,
                          &chunk_received, &eof, buf + total_read);

        if (ret != AFP_SERVER_RESULT_OKAY) {
            if (total_read > 0) {
                return total_read;  /* Return what we got */
            }
            return sl_result_to_errno(ret);
        }

        total_read += chunk_received;

        if (chunk_received == 0) {
            break;
        }
    }

    return total_read;
}

/*
 * FUSE write - write to a file
 */
static int sl_write(const char *path, const char *buf, size_t size,
                    off_t offset, struct fuse_file_info *fi)
{
    (void) path;
    struct stateless_file_handle *fh;
    size_t total_written = 0;
    int ret;

    if (!fi || !fi->fh) {
        return -EBADF;
    }

    fh = (struct stateless_file_handle *)(uintptr_t)fi->fh;

    /* Write in chunks to match AFP max packet size */
    while (total_written < size) {
        unsigned int chunk_written = 0;
        unsigned int chunk_size = size - total_written;

        if (chunk_size > 65536) {
            chunk_size = 65536;
        }

        ret = afp_sl_write(&fh->volumeid, fh->fileid, 0,
                           offset + total_written, chunk_size,
                           buf + total_written, &chunk_written);

        if (ret != AFP_SERVER_RESULT_OKAY) {
            if (total_written > 0) {
                return total_written;
            }
            return sl_result_to_errno(ret);
        }

        total_written += chunk_written;

        if (chunk_written == 0) {
            break;  /* Avoid infinite loop */
        }
    }

    return total_written;
}

/*
 * FUSE flush - flush cached data
 */
static int sl_flush(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    struct stateless_file_handle *fh;
    int ret;

    if (!fi || !fi->fh) {
        return 0;
    }

    fh = (struct stateless_file_handle *)(uintptr_t)fi->fh;

    ret = afp_sl_flush(&fh->volumeid, fh->fileid);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }

    return 0;
}

/*
 * FUSE release - close a file
 */
static int sl_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    struct stateless_file_handle *fh;

    if (!fi || !fi->fh) {
        return 0;
    }

    fh = (struct stateless_file_handle *)(uintptr_t)fi->fh;

    afp_sl_close(&fh->volumeid, fh->fileid);
    free(fh);
    fi->fh = 0;

    return 0;
}

/*
 * FUSE mkdir - create a directory
 */
static int sl_mkdir(const char *path, mode_t mode)
{
    int ret = afp_sl_mkdir(&mount_volumeid, path, mode);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE rmdir - remove a directory
 */
static int sl_rmdir(const char *path)
{
    int ret = afp_sl_rmdir(&mount_volumeid, path);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE unlink - remove a file
 */
static int sl_unlink(const char *path)
{
    int ret = afp_sl_unlink(&mount_volumeid, path);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE rename - rename a file or directory
 */
#if FUSE_NEW_API
static int sl_rename(const char *from, const char *to, unsigned int flags)
{
    (void) flags;
#else
static int sl_rename(const char *from, const char *to)
{
#endif
    int ret = afp_sl_rename(&mount_volumeid, from, to);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE truncate - truncate a file
 */
#if FUSE_NEW_API
static int sl_truncate(const char *path, off_t size, struct fuse_file_info *fi)
{
    int ret;

    if (fi && fi->fh) {
        /* Use ftruncate on open file */
        struct stateless_file_handle *fh;
        fh = (struct stateless_file_handle *)(uintptr_t)fi->fh;
        ret = afp_sl_ftruncate(&fh->volumeid, fh->fileid, size);
    } else {
        /* Truncate by path */
        ret = afp_sl_truncate(&mount_volumeid, path, size);
    }

    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}
#else
static int sl_truncate(const char *path, off_t size)
{
    int ret = afp_sl_truncate(&mount_volumeid, path, size);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}
#endif

/*
 * FUSE chmod - change file mode
 */
#if FUSE_NEW_API
static int sl_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void) fi;
#else
static int sl_chmod(const char *path, mode_t mode)
{
#endif
    int ret = afp_sl_chmod(&mount_volumeid, path, mode);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE chown - change file owner
 */
#if FUSE_NEW_API
static int sl_chown(const char *path, uid_t uid, gid_t gid,
                    struct fuse_file_info *fi)
{
    (void) fi;
#else
static int sl_chown(const char *path, uid_t uid, gid_t gid)
{
#endif
    int ret = afp_sl_chown(&mount_volumeid, path, uid, gid);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE utimens / utime - change file timestamps
 */
#if FUSE_USE_VERSION >= 30
#if FUSE_NEW_API
static int sl_utimens(const char *path, const struct timespec tv[2],
                      struct fuse_file_info *fi)
{
    (void) fi;
#else
static int sl_utimens(const char *path, const struct timespec tv[2])
{
#endif
    long atime_sec, atime_nsec, mtime_sec, mtime_nsec;

    if (tv) {
        atime_sec = tv[0].tv_sec;
        atime_nsec = tv[0].tv_nsec;
        mtime_sec = tv[1].tv_sec;
        mtime_nsec = tv[1].tv_nsec;
    } else {
        time_t now = time(NULL);
        atime_sec = now;
        atime_nsec = 0;
        mtime_sec = now;
        mtime_nsec = 0;
    }

    int ret = afp_sl_utime(&mount_volumeid, path, atime_sec, atime_nsec,
                           mtime_sec, mtime_nsec);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}
#else
static int sl_utime(const char *path, struct utimbuf *timebuf)
{
    long atime_sec, mtime_sec;

    if (timebuf) {
        atime_sec = timebuf->actime;
        mtime_sec = timebuf->modtime;
    } else {
        time_t now = time(NULL);
        atime_sec = now;
        mtime_sec = now;
    }

    int ret = afp_sl_utime(&mount_volumeid, path, atime_sec, 0, mtime_sec, 0);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}
#endif

/*
 * FUSE symlink - create a symbolic link
 */
static int sl_symlink(const char *target, const char *linkpath)
{
    int ret = afp_sl_symlink(&mount_volumeid, target, linkpath);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE readlink - read a symbolic link
 */
static int sl_readlink(const char *path, char *buf, size_t size)
{
    int ret = afp_sl_readlink(&mount_volumeid, path, buf, size);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}

/*
 * FUSE mknod - create a file node
 */
static int sl_mknod(const char *path, mode_t mode,
                    __attribute__((unused)) dev_t dev)
{
    /* For regular files, use create */
    unsigned int fileid;
    int ret = afp_sl_create(&mount_volumeid, path, O_WRONLY, mode, &fileid);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    /* Close immediately - mknod just creates the file */
    afp_sl_close(&mount_volumeid, fileid);
    return 0;
}

/*
 * FUSE statfs - get filesystem statistics
 */
#ifdef __APPLE__
static int sl_statfs(const char *path, struct statfs *stat)
{
    unsigned long long blocks, bfree, bavail, files, ffree;
    unsigned int bsize, namelen;

    int ret = afp_sl_statfs(&mount_volumeid, path, &blocks, &bfree, &bavail,
                            &files, &ffree, &bsize, &namelen);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }

    memset(stat, 0, sizeof(*stat));
    stat->f_bsize = bsize;
    stat->f_blocks = blocks;
    stat->f_bfree = bfree;
    stat->f_bavail = bavail;
    stat->f_files = files;
    stat->f_ffree = ffree;

    return 0;
}
#else
static int sl_statfs(const char *path, struct statvfs *stat)
{
    unsigned long long blocks, bfree, bavail, files, ffree;
    unsigned int bsize, namelen;

    int ret = afp_sl_statfs(&mount_volumeid, path, &blocks, &bfree, &bavail,
                            &files, &ffree, &bsize, &namelen);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }

    memset(stat, 0, sizeof(*stat));
    stat->f_bsize = bsize;
    stat->f_frsize = bsize;
    stat->f_blocks = blocks;
    stat->f_bfree = bfree;
    stat->f_bavail = bavail;
    stat->f_files = files;
    stat->f_ffree = ffree;
    stat->f_namemax = namelen;

    return 0;
}
#endif

/*
 * Extended attributes
 */
#ifdef __APPLE__
static int sl_getxattr(const char *path, const char *name, char *value,
                       size_t size, uint32_t position)
{
    if (position != 0) {
        return -EOPNOTSUPP;
    }
#else
static int sl_getxattr(const char *path, const char *name, char *value,
                       size_t size)
{
#endif
    int actual_size = 0;
    int ret = afp_sl_getxattr(&mount_volumeid, path, name, value, size,
                              &actual_size);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return actual_size;
}

#ifdef __APPLE__
static int sl_setxattr(const char *path, const char *name, const char *value,
                       size_t size, int flags, uint32_t position)
{
    if (position != 0) {
        return -EOPNOTSUPP;
    }
    /* macFUSE bug workaround: EA writes are unreliable */
    (void) flags;
    return -ENOTSUP;
}
#else
static int sl_setxattr(const char *path, const char *name, const char *value,
                       size_t size, int flags)
{
    int ret = afp_sl_setxattr(&mount_volumeid, path, name, value, size, flags);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
}
#endif

static int sl_listxattr(const char *path, char *list, size_t size)
{
    int actual_size = 0;
    int ret = afp_sl_listxattr(&mount_volumeid, path, list, size, &actual_size);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return actual_size;
}

static int sl_removexattr(const char *path, const char *name)
{
#ifdef __APPLE__
    /* macFUSE bug workaround */
    (void) path;
    (void) name;
    return -ENOTSUP;
#else
    int ret = afp_sl_removexattr(&mount_volumeid, path, name);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        return sl_result_to_errno(ret);
    }
    return 0;
#endif
}

#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
static int sl_chflags(__attribute__((unused)) const char *path,
                      __attribute__((unused)) struct fuse_file_info *fi,
                      __attribute__((unused)) unsigned int flags)
{
    /* AFP doesn't support BSD file flags */
    return 0;
}
#endif

/*
 * Initialization and cleanup
 */
#if FUSE_NEW_API
static void *sl_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void) conn;
    (void) cfg;
    return NULL;
}
#else
static void *sl_init(__attribute__((unused)) struct fuse_conn_info *conn)
{
    return NULL;
}
#endif

static void sl_destroy(__attribute__((unused)) void *userdata)
{
    /* Detach from volume when unmounting */
    afp_sl_detach(&mount_volumeid);
}

/*
 * FUSE operations structure
 */
static struct fuse_operations sl_oper = {
#if defined(__APPLE__) && FUSE_USE_VERSION >= 30
    .getattr    = sl_getattr_darwin,
    .readdir    = sl_readdir_darwin,
    .chflags    = sl_chflags,
#else
    .getattr    = sl_getattr,
    .readdir    = sl_readdir,
#endif
    .open       = sl_open,
    .read       = sl_read,
    .mkdir      = sl_mkdir,
    .readlink   = sl_readlink,
    .rmdir      = sl_rmdir,
    .unlink     = sl_unlink,
    .mknod      = sl_mknod,
    .create     = sl_create,
    .write      = sl_write,
    .flush      = sl_flush,
    .release    = sl_release,
    .getxattr   = sl_getxattr,
    .setxattr   = sl_setxattr,
    .listxattr  = sl_listxattr,
    .removexattr = sl_removexattr,
    .chmod      = sl_chmod,
    .symlink    = sl_symlink,
    .chown      = sl_chown,
    .truncate   = sl_truncate,
    .rename     = sl_rename,
#if FUSE_USE_VERSION >= 30
    .utimens    = sl_utimens,
#else
    .utime      = sl_utime,
#endif
    .destroy    = sl_destroy,
    .init       = sl_init,
    .statfs     = sl_statfs,
};

/*
 * Entry point for stateless FUSE mount
 *
 * This function connects to the daemon, attaches to a volume,
 * and starts the FUSE event loop.
 */
int afp_sl_fuse_mount(struct afp_url *url,
                      __attribute__((unused)) const char *mountpoint,
                      unsigned int volume_options, int argc, char *argv[])
{
    int ret;

    /* Connect to daemon */
    ret = afp_sl_setup();
    if (ret < 0) {
        fprintf(stderr, "Failed to connect to afpfsd daemon: %s\n",
                strerror(-ret));
        return ret;
    }

    /* Attach to volume */
    ret = afp_sl_attach(url, volume_options, &mount_volumeid);
    if (ret != AFP_SERVER_RESULT_OKAY) {
        fprintf(stderr, "Failed to attach to volume: error %d\n", ret);
        return -1;
    }

    /* Start FUSE */
    fuse_capture_stderr_start();
    ret = fuse_main(argc, argv, &sl_oper, NULL);

    return ret;
}

/*
 * Alternative entry point that uses an already-attached volume
 */
int afp_sl_fuse_mount_with_volid(volumeid_t *volid, int argc, char *argv[])
{
    int ret;

    memcpy(&mount_volumeid, volid, sizeof(volumeid_t));

    fuse_capture_stderr_start();
    ret = fuse_main(argc, argv, &sl_oper, NULL);

    return ret;
}

/*
 * Main entry point for standalone stateless FUSE mount
 *
 * Usage: mount_afpfs_sl <afp_url> <mountpoint> [fuse_options...]
 *
 * Example: mount_afpfs_sl afp://user:pass@server/volume /mnt/afp
 */
int main(int argc, char *argv[])
{
    struct afp_url url;
    char *url_string;
    int fuse_argc;
    char **fuse_argv;
    int ret;
    int i;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <afp_url> <mountpoint> [fuse_options...]\n", argv[0]);
        fprintf(stderr, "\nStateless AFP FUSE mount client\n");
        fprintf(stderr, "All file operations are handled by the afpfsd daemon.\n");
        fprintf(stderr, "\nExample:\n");
        fprintf(stderr, "  %s afp://user:pass@server/volume /mnt/afp\n", argv[0]);
        fprintf(stderr, "  %s afp://server/volume /mnt/afp -o allow_other\n", argv[0]);
        return 1;
    }

    url_string = argv[1];

    /* Parse the AFP URL */
    memset(&url, 0, sizeof(url));
    if (afp_parse_url(&url, url_string, 0) != 0) {
        fprintf(stderr, "Failed to parse AFP URL: %s\n", url_string);
        return 1;
    }

    /* Build FUSE argument list: program name, mountpoint, -f (foreground), and any extra options */
    /* We add -f to ensure FUSE runs in foreground since the daemon handles state */
    fuse_argc = argc;  /* Remove AFP URL but add -f */
    fuse_argv = malloc(sizeof(char *) * (fuse_argc + 2));
    if (!fuse_argv) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    fuse_argv[0] = argv[0];           /* Program name */
    fuse_argv[1] = argv[2];           /* Mountpoint */
    fuse_argv[2] = "-f";              /* Run in foreground */
    for (i = 3; i < argc; i++) {
        fuse_argv[i] = argv[i];       /* Additional FUSE options */
    }
    fuse_argv[fuse_argc] = NULL;

    /* Connect to daemon and mount */
    ret = afp_sl_fuse_mount(&url, argv[2], 0, fuse_argc, fuse_argv);

    free(fuse_argv);
    return ret;
}
