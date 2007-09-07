#ifndef __VOLINFO_H_
#define __VOLINFO_H_

unsigned char is_volinfo(const char * path);

#ifdef FIXME
int volinfo_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
        off_t offset, struct fuse_file_info *fi);
#endif

int volinfo_getattr(const char *path, struct stat *stbuf);

int volinfo_open(struct afp_volume * volume, const char *path);

int volinfo_read(struct afp_volume * volume, const char *path,
        char *buf, size_t size, off_t offset, struct afp_file_info * fp);

int volinfo_write(struct afp_volume * volume, const char *path,
        const char *data, size_t size, off_t offset,
        struct afp_file_info * fp);

#endif
