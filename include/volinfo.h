#ifndef __VOLINFO_H_
#define __VOLINFO_H_

unsigned char is_volinfo(const char * path);

int volinfo_readdir(const char *path, struct afp_file_info **base);

int volinfo_getattr(const char *path, struct stat *stbuf);

int volinfo_open(struct afp_volume * volume, const char *path);

int volinfo_read(struct afp_volume * volume, const char *path,
        char *buf, size_t size, off_t offset, struct afp_file_info * fp);

int volinfo_write(struct afp_volume * volume, const char *path,
        const char *data, size_t size, off_t offset,
        struct afp_file_info * fp);

#endif
