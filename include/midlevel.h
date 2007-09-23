#ifndef __MIDLEVEL_H_
#define __MIDLEVEL_H_ 


int get_unixprivs(struct afp_volume * volume,
        unsigned int dirid, 
        const char * path, struct afp_file_info * fp);

int set_unixprivs(struct afp_volume * volume,
        unsigned int dirid, 
        const char * basename, struct afp_file_info * fp);

int ml_chmod(struct afp_volume * vol, const char * path, mode_t mode);

int ml_mkdir(struct afp_volume * vol, const char * path, mode_t mode);

int ml_unlink(struct afp_volume * vol, const char *path);





int ml_readdir(struct afp_volume * volume, 
	const char *path, 
	struct afp_file_info **base);

int ml_read(const char *path, char *buf, size_t size, off_t offset,
	struct afp_volume * volume, struct afp_file_info *fp,
	int * eof);

int ml_open(const char *path, int flags, struct afp_volume * volume,
        struct afp_file_info **newfp);

int ml_close(const char * path, struct afp_volume * volume,
        struct afp_file_info * fp);

int ml_write(const char * path, struct afp_volume * volume,
	const char *data, size_t size, off_t offset,
	struct afp_file_info * fp, uid_t uid,
	gid_t gid);

int ml_open(const char *path, int flags, struct afp_volume * volume,
        struct afp_file_info **newfp);

int ml_creat(struct afp_volume * volume, const char *path,mode_t mode);

int ml_readlink(struct afp_volume * vol, const char * path,
        char *buf, size_t size);

int ml_rmdir(struct afp_volume * vol, const char *path);

int ml_chown(struct afp_volume * vol, const char * path,   
        uid_t uid, gid_t gid);

int ml_utime(struct afp_volume * vol, const char * path,
	struct utimbuf * timebuf);

int ml_symlink(struct afp_volume *vol, const char * path1, const char * path2);

int ml_rename(struct afp_volume * vol,
	const char * path_from, const char * path_to);

int ml_statfs(struct afp_volume * vol, const char *path, struct statvfs *stat);

int ml_truncate(struct afp_volume * vol, const char * path, off_t offset);

int ml_getattr(struct afp_volume * volume, const char *path, struct stat *stbuf);

int handle_unlocking(struct afp_volume * volume,unsigned short forkid,
	uint64_t offset, uint64_t sizetorequest);

int handle_locking(struct afp_volume * volume,unsigned short forkid, 
	uint64_t offset, uint64_t sizetorequest);

#endif
