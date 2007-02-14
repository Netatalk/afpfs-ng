

/*


    Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include <fuse.h>
#include <fuse/fuse_opt.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <utime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <syslog.h>

#include "afp.h"
#include "dsi.h"
#include "afp_protocol.h"
#include "utils.h"
#include "log.h"
#include "meta.h"

#define VOLINFO_PATH "/.afpvolinfo"
#define query_size 12

unsigned char is_volinfo(const char * path) 
{
	char * p = strstr(path,VOLINFO_PATH);
	if (!p) return 0;

	return (strncmp(path,VOLINFO_PATH,strlen(VOLINFO_PATH))==0);
}

static char * after_volinfo(const char * p)
{
	return (p+strlen(VOLINFO_PATH));
}

static unsigned char is_icon(const char * path) 
{
	return (strcmp(path,"/servericon")==0);
}

static unsigned char is_geticon(const char * path) 
{
	return (strcmp(path,"/geticon")==0);
}

int volinfo_open(const char *path, struct fuse_file_info *fi) 
{
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char * p;

	p=after_volinfo(path);
	if (!p) return 0;
	if (is_icon(p)) {
		return 0;

	} else if (is_geticon(p)) {
		afp_opendt(volume,&volume->dtrefnum);
		return 0;

	} else {
		return -ENOENT;
	}
	return 0;
}

int volinfo_getattr(const char *path, struct stat *stbuf)
{
	char * p;
	if (strlen(path)==strlen(VOLINFO_PATH)) {
		stbuf->st_mode=S_IFDIR | 0755;
		stbuf->st_nlink=2;
		return 0;
	}

	p=after_volinfo(path);
	if (is_icon(p)) {
		stbuf->st_mode=S_IFREG| 0444;
		stbuf->st_size=256;
		stbuf->st_nlink=1;
	} else if (is_geticon(p)) {
		stbuf->st_mode=S_IFREG | 0644;
		stbuf->st_size=256;
		stbuf->st_nlink=1;
	}
	return 0;
}

int volinfo_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	off_t offset, struct fuse_file_info *fi)
{
	filler(buf,"servericon",NULL,0);
	filler(buf,"geticon",NULL,0);
	return 0;
}

int volinfo_write(const char *path, const char *data, size_t size, 
	off_t offset, struct fuse_file_info *fi)
{
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	int rc;
	char *p;
	struct afp_file_info * fp;

	fp=(void *)fi->fh;

	p=after_volinfo(path);

	if (is_geticon(p)) {
		struct query_geticon * query = (void *) data;
		fp->icon=malloc(sizeof(struct afp_icon));
		fp->icon->size=0;
		fp->icon->maxsize=256;
		fp->icon->data=malloc(fp->icon->maxsize);
		if (size<sizeof(*query)) {
			return -EIO;
		}
		rc=afp_geticon(volume,query->filecreator,
			query->filetype,query->icontype, query->length,
			fp->icon);
		return sizeof(*query);
		
	} else {
		return -ENOENT;
	}
	return 0;

}

int volinfo_read(const char *path, char *buf, size_t size, off_t offset,
	struct fuse_file_info *fi)
{
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	unsigned int len = size;
	char * p=after_volinfo(path);
	struct afp_file_info * fp;

	fp=(void *)fi->fh;

	if (is_icon(p)) {
		len=min(len,256-offset);
		memcpy(buf,volume->server->icon,len);
	} else if (is_geticon(p)) {
		len=min(len,fp->icon->maxsize-offset);
		if (len<0) return -ENOENT;
		fp->icon->size+=len;
		memcpy(buf+query_size,fp->icon->data,len);
	} else {
		return -ENOENT;
	}
	return len;
}
