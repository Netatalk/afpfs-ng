#ifndef __VOLINFO_H_
#define __VOLINFO_H_

#include <fuse.h>

unsigned char is_volinfo(const char * path);

int volinfo_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *fi);

int volinfo_getattr(const char *path, struct stat *stbuf);

int volinfo_open(const char *path, struct fuse_file_info *fi);

int volinfo_read(const char *path, char *buf, size_t size, off_t offset,
        struct fuse_file_info *fi);

int volinfo_write(const char *path, const char *data, size_t size,
        off_t offset, struct fuse_file_info *fi);

#endif
