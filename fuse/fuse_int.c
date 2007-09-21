

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
#ifdef __linux__
#include <asm/fcntl.h>
#else
#include <fcntl.h>
#endif

#include <utime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>

#include "dsi.h"
#include "afp_protocol.h"
#include "utils.h"
#include "log.h"
#include "volinfo.h"
#include "did.h"
#include "resource.h"
#include "users.h"
#include "codepage.h"
#include "midlevel.h"

/* Uncomment the following line to enable full debugging: */
/* #define LOG_FUSE_EVENTS 1 */

#ifdef LOG_FUSE_EVENTS
#define log_fuse_event LOG
#else
void log_fuse_event(enum loglevels loglevel, int logtype,
                    char *message, ...) {

}
#endif

static struct afp_volume * global_volume;


/* zero_file()
 *
 * This function will truncate the fork given to zero bytes in length.
 * This has been abstracted because there is some differences in the
 * expectation of Ext or not Ext. */

static int zero_file(struct afp_volume * volume, unsigned short forkid,
	unsigned int resource)
{
	unsigned int bitmap;
	int ret;

	/* The Airport Extreme 7.1.1 will crash if you send it
	 * DataForkLenBit.  Netatalk replies with an error if you
	 * send it ExtDataForkLenBit.  So we need to choose. */

	if ((volume->server->using_version->av_number < 30)  ||
		(volume->server->server_type==AFPFS_SERVER_TYPE_NETATALK))
		bitmap=(resource ? 
			kFPRsrcForkLenBit : kFPDataForkLenBit);
	else
		bitmap=(resource ? 
			kFPExtRsrcForkLenBit : kFPExtDataForkLenBit);

	ret=afp_setforkparms(volume,forkid,bitmap,0);
	switch (ret) {
		case kFPAccessDenied:
			ret=EACCES;
			break;
		case kFPVolLocked:
		case kFPLockErr:
			ret=EBUSY;
			break;
		case kFPDiskFull:
			ret=ENOSPC;
			break;
		case kFPBitmapErr:
		case kFPMiscErr:
		case kFPParamErr:
			ret=EIO;
			break;
		default:
			ret=0;
	}
	return ret;
}

static int afp_getattr(const char *path, struct stat *stbuf)
{
	char * c;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	int rc;

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** getattr of %s\n",path);

	/* Oddly, we sometimes get <dir1>/<dir2>/(null) for the path */

	if (!path) return -EIO;

	if ((c=strstr(path,"(null)"))) {
		/* We should fix this to make sure it is at the end */
		if (c>path) *(c-1)='\0';
	}

	rc= ml_getattr(volume,path,stbuf);

	return rc;

#if 0
	memset(stbuf, 0, sizeof(struct stat));

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_volinfo(converted_path)) 
		return volinfo_getattr(converted_path,stbuf);

	if (is_apple(converted_path)) 
	{
		if (is_double_apple(converted_path))
			return -ENOENT;
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink=2;
		return 0;
	}

	resource=apple_translate(volume,converted_path);

	if ((volume->server) && 
		(invalid_filename(volume->server,converted_path)))
		return -ENAMETOOLONG;

	get_dirid(volume, converted_path, basename, &dirid);

	if ((volume->server->using_version->av_number < 30) && 
		(path[0]=='/' && path[1]=='\0')) {
		/* This will sound odd, but when referring to /, AFP 2.x
		   clients check on a 'file' with the volume name. */
		snprintf(basename,AFP_MAX_PATH,"%s",volume->name);
		dirid=1;
	}


	dirbitmap=kFPAttributeBit 
		| kFPCreateDateBit | kFPModDateBit|
		kFPNodeIDBit |
		kFPParentDirIDBit | kFPOffspringCountBit;
	filebitmap=kFPAttributeBit | 
		kFPCreateDateBit | kFPModDateBit |
		kFPNodeIDBit |
		kFPFinderInfoBit |
		kFPParentDirIDBit | 
		((resource==AFP_RESOURCE_TYPE_RESOURCE) ? 
			kFPExtRsrcForkLenBit : kFPExtDataForkLenBit );

	if (volume->attributes &kSupportsUnixPrivs) {
		dirbitmap|= kFPUnixPrivsBit;
		filebitmap|= kFPUnixPrivsBit;
	}

	rc=afp_getfiledirparms(volume,dirid,filebitmap,dirbitmap,
		(char *) basename,&fp);

	switch(rc) {
		
	case kFPAccessDenied:
		return -EACCES;
	case kFPObjectNotFound:
		return -ENOENT;
	case kFPNoErr:
		break;
	case kFPBitmapErr:
	case kFPMiscErr:
	case kFPParamErr:
	default:
		return -EIO;
	}
	if (volume->server->using_version->av_number>=30)
		stbuf->st_mode |= fp.unixprivs.permissions;
	else
		stbuf->st_mode |= 0755;
	if (stbuf->st_mode & S_IFDIR) {
		stbuf->st_nlink = fp.offspring +2;  
		stbuf->st_size = (fp.offspring *34) + 24;  
			/* This slight voodoo was taken from Mac OS X 10.2 */
	} else {
		stbuf->st_nlink = 1;
		stbuf->st_size = (resource ? fp.resourcesize : fp.size);
	}

	stbuf->st_uid=fp.unixprivs.uid;
	stbuf->st_gid=fp.unixprivs.gid;
	if (translate_uidgid_to_client(volume,
		&stbuf->st_uid,&stbuf->st_gid)) 
		return -EIO;

#ifdef __linux__
	stbuf->st_ctim.tv_sec=fp.creation_date;
	stbuf->st_mtim.tv_sec=fp.modification_date;
#else
	stbuf->st_ctime=fp.creation_date;
	stbuf->st_mtime=fp.modification_date;
#endif

	if (resource==AFP_RESOURCE_TYPE_PARENT2) {
		stbuf->st_mode |= S_IFDIR;
		stbuf->st_mode &=~S_IFREG;
 		stbuf->st_mode |=S_IXUSR | S_IXGRP | S_IXOTH;
	}
	switch (resource) {
	case AFP_RESOURCE_TYPE_FINDERINFO:
		stbuf->st_size=32;
		break;
	case AFP_RESOURCE_TYPE_COMMENT:
		{
        	struct afp_comment comment;
		if (!volume->dtrefnum) {
			switch(afp_opendt(volume,&volume->dtrefnum)) {
			case kFPParamErr:
			case kFPMiscErr:
				return -EIO;
				break;
			case kFPNoErr:
			default:
				break;
			}
		} 
		comment.size=0;
		comment.maxsize=200;
		comment.data=malloc(200);
		switch(afp_getcomment(volume,dirid, basename,&comment)) {
		case kFPAccessDenied:
			return -EACCES;
		case kFPMiscErr:
		case kFPParamErr:
			return -EIO;
		case kFPItemNotFound:
		case kFPObjectNotFound:  /* we'll leave this as size 0 */
		case kFPNoErr:
		default:
			break;
		}
		stbuf->st_size=comment.size;
		free(comment.data);
		}
	}
	return 0;
#endif

}

static int afp_readlink(const char * path, char *buf, size_t size)
{
	int rc,ret;
	struct afp_file_info fp;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	struct afp_rx_buffer buffer;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	unsigned int dirid;
	char link_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** readlink of %s\n",path);

	memset(buf,0,size);
	memset(link_path,0,AFP_MAX_PATH);

	buffer.data=link_path;
	buffer.maxsize=size;
	buffer.size=0;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(volume, converted_path, basename, &dirid);

	/* Open the fork */
	rc=afp_openfork(volume,0, dirid, 
		AFP_OPENFORK_ALLOWWRITE|AFP_OPENFORK_ALLOWREAD,
		basename,&fp);
	switch (rc) {
	case kFPAccessDenied:
		ret=EACCES;
		goto error;
	case kFPObjectNotFound:
		ret=ENOENT;
		goto error;
	case kFPObjectLocked:
		ret=EROFS;
		goto error;
	case kFPObjectTypeErr:
		ret=EISDIR;
		goto error;
	case kFPParamErr:
		ret=EACCES;
		goto error;
	case kFPTooManyFilesOpen:
		ret=EMFILE;
		goto error;
	case kFPVolLocked:
	case kFPDenyConflict:
	case kFPMiscErr:
	case kFPBitmapErr:
	case -1:
		LOG(AFPFSD,LOG_WARNING,
			"Got some sort of internal error in afp_open for readlink\n");
		ret=EFAULT;
		goto error;
	case 0:
		ret=0;
		break;
	default:
		LOG(AFPFSD,LOG_WARNING,
			"Got some sort of other error in afp_open for readlink\n");
		ret=EFAULT;
		goto error;
	}

	/* Read the name of the file from it */
	rc=afp_readext(volume, fp.forkid,0,size,&buffer);
	switch(rc) {
	case kFPAccessDenied:
		ret=EACCES;
		goto error;
	case kFPLockErr:
		ret=EBUSY;
		goto error;
	case kFPMiscErr:
	case kFPParamErr:
		ret=EIO;
		goto error;
	case kFPEOFErr:
	case kFPNoErr:
		break;
	}

	switch(afp_closefork(volume,fp.forkid)) {
	case kFPNoErr:
		break;
	default:
	case kFPParamErr:
	case kFPMiscErr:
		ret=EIO;
		goto error;
	}

	/* Convert the name back precomposed UTF8 */
	convert_path_to_unix(volume->server->path_encoding,
		buf,(char *) link_path,AFP_MAX_PATH);

	return 0;
	
error:
	return -ret;
}

static int afp_rmdir(const char *path)
{
	int ret,rc;
	unsigned int dirid;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];

	if (volume_is_readonly(volume))
		return -EPERM;

	if (invalid_filename(volume->server,path)) 
		return -ENAMETOOLONG;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (apple_translate(volume,converted_path))
		return 0;

	if (is_apple(converted_path)) 
		return 0;

	get_dirid(volume, converted_path, basename, &dirid);

	if (!is_dir(volume,dirid,basename)) return -ENOTDIR;

	rc=afp_delete(volume,dirid,basename);

	switch(rc) {
	case kFPAccessDenied:
		ret=EACCES;
		break;
	case kFPObjectLocked:
		ret=EBUSY;
		break;
	case kFPObjectNotFound:
		ret=ENOENT;
		break;
	case kFPVolLocked:
		ret=EACCES;
		break;
	case kFPDirNotEmpty:
		ret=ENOTEMPTY;
		break;
	case kFPObjectTypeErr:
	case kFPMiscErr:
	case kFPParamErr:
	case -1:
		ret=EINVAL;
		break;
	default:
		remove_did_entry(volume,converted_path);
		ret=0;
	}
	return -ret;
}

static int afp_unlink(const char *path)
{
	int ret,rc;
	unsigned int dirid;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** unlink of %s\n",path);

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_apple(converted_path))
		return 0;

	if (apple_translate(volume,converted_path))
		return 0;

	get_dirid(volume, (char * ) converted_path, basename, &dirid);

	if (is_dir(volume,dirid,basename) ) return -EISDIR;

	if (invalid_filename(volume->server,converted_path)) 
		return -ENAMETOOLONG;

	rc=afp_delete(volume,dirid,basename);

	switch(rc) {
	case kFPAccessDenied:
		ret=EACCES;
		break;
	case kFPObjectLocked:
		ret=EBUSY;
		break;
	case kFPObjectNotFound:
		ret=ENOENT;
		break;
	case kFPVolLocked:
		ret=EACCES;
		break;
	case kFPObjectTypeErr:
	case kFPDirNotEmpty:
	case kFPMiscErr:
	case kFPParamErr:
	case -1:
		ret=EINVAL;
		break;
	default:
		ret=0;
	}
	return -ret;
}


static int afp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;
	struct afp_file_info * filebase = NULL, * p, *prev;
	int ret;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** readdir of %s\n",path);

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	ret=ml_readdir(volume,path,&filebase);

	if (ret) goto error;

	for (p=filebase;p;) {
		filler(buf,p->name,NULL,0);
		prev=p;
		p=p->next;
		free(prev);
	}

done:
    return 0;

error:
	return ret;
}

static int afp_mknod(const char *path, mode_t mode, dev_t dev)
{
	int ret=0;
	struct fuse_context * context = fuse_get_context();
	struct afp_volume * volume=
		(struct afp_volume *) context->private_data;
	char resource;
	char basename[AFP_MAX_PATH];
	unsigned int dirid;
	struct afp_file_info fp;
	int rc;
	char converted_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** mknod of %s\n",path);

	rc=ml_creat(volume,path,mode);

	return rc;
}


static int afp_release(const char * path, struct fuse_file_info * fi)
{

	struct afp_file_info * fp = (void *) fi->fh;
	int ret=0;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char converted_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** release of %s\n",path);

	ret=ml_close(path,volume,fp);

	if (ret<0) goto error;

	return ret;
error:
	free((void *) fi->fh);
	return ret;
}

static int afp_open(const char *path, struct fuse_file_info *fi)
{

	struct afp_file_info * fp ;
	int ret;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	unsigned char flags = AFP_OPENFORK_ALLOWREAD;

	log_fuse_event(AFPFSD,LOG_DEBUG,
		"*** Opening path %s\n",path);

	ret = ml_open(path,flags,volume,&fp);

	if (ret==0) 
		fi->fh=fp;

	return ret;
}


int afp_write(const char * path, const char *data, size_t size, off_t offset,
                  struct fuse_file_info *fi)
{

	struct afp_file_info *fp = (struct afp_file_info *) fi->fh;
	int ret;
	struct fuse_context * context = fuse_get_context();
	struct afp_volume * volume=(void *) context->private_data;

	log_fuse_event(AFPFSD,LOG_DEBUG,
		"*** write of from %llu for %llu\n",
		(unsigned long long) offset,(unsigned long long) size);

	ret=ml_write(path,volume,data,size,offset,fp,
		context->uid, context->gid);


	return ret;

}


static int afp_mkdir(const char * path, mode_t mode) 
{
	int ret,rc;
	unsigned int result_did;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	unsigned int dirid;

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** mkdir of %s\n",path);

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (invalid_filename(volume->server,path)) 
		return -ENAMETOOLONG;

	get_dirid(volume,converted_path,basename,&dirid);

	rc = afp_createdir_request(volume,dirid, basename,&result_did);

	switch (rc) {
	case kFPAccessDenied:
		ret = EACCES;
		break;
	case kFPDiskFull:
		ret = ENOSPC;
		break;
	case kFPObjectNotFound:
		ret = ENOENT;
		break;
	case kFPObjectExists:
		ret = EEXIST;
		break;
	case kFPVolLocked:
		ret = EBUSY;
		break;
	case kFPFlatVol:
	case kFPMiscErr:
	case kFPParamErr:
	case -1:
		ret = EFAULT;
		break;
	default:
		ret =0;
	}

	return -ret;
}
static int afp_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi)
{
	struct afp_file_info * fp;	
	int ret=0;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	int eof;

	if (!fi || !fi->fh) 
		return -EBADF;
	fp=(void *) fi->fh;

	ret=ml_read(path,buf,size,offset,volume,fp,&eof);

	return ret;
}

static int afp_chown(const char * path, uid_t uid, gid_t gid) 
{

	struct afp_file_info fp;
	int rc;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	unsigned int dirid;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,"** chown\n");

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (invalid_filename(volume->server,converted_path)) 
		return -ENAMETOOLONG;

	/* There's no way to do this in AFP < 3.0 */
	if ((volume->server->using_version->av_number < 30) ||
		(~ volume->attributes & kSupportsUnixPrivs)) {
		return -ENOSYS;
	};

	get_dirid(volume,converted_path,basename,&dirid );

	if ((rc=get_unixprivs(volume,
		dirid,basename, &fp)))
		return rc;

#if 0
FIXME
	set_uidgid(volume,&fp,uid,gid);
THIS IS the wrong set of returns to check...
#endif
	rc=set_unixprivs(volume, dirid, basename, &fp);

	switch(rc) {
	case -ENOSYS:
		LOG(AFPFSD,LOG_WARNING,"chmod unsupported\n");
		break;
	case kFPNoErr:
		break;
	case kFPAccessDenied:
		return -EACCES;
	case kFPObjectNotFound:
		return -ENOENT;
	case kFPBitmapErr:
	case kFPMiscErr:
	case kFPObjectTypeErr:
	case kFPParamErr:
	default:
		break;

	}

	return 0;
}

static int afp_truncate(const char * path, off_t offset)
{
	int ret=0;
	unsigned short forkid;
	struct fuse_file_info fi;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char converted_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,
		"** truncate\n");

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	/* The approach here is to get the forkid by calling afp_open()
	   (and not afp_openfork).  Note the fake fuse_file_info used
	   just to grab this forkid. */

	fi.flags=O_WRONLY;
	if (invalid_filename(volume->server,converted_path)) 
		return -ENAMETOOLONG;

	if (is_volinfo(converted_path)) return 0;

	switch (apple_translate(volume,converted_path)) {
		case AFP_RESOURCE_TYPE_FINDERINFO:
		case AFP_RESOURCE_TYPE_COMMENT:
			/* Remove comment */
			return 0;
		default:
			break;
	}

	/* Here, we're going to use the untranslated path since it is
	   translated through the afp_open() */

	if ((ret=afp_open(path,&fi)) ) {
		return ret;
	};

	forkid=((struct afp_file_info *) fi.fh)->forkid;

	if ((ret=zero_file(volume,forkid,0)))
		goto out;

	afp_closefork(volume,forkid);

out:
	return -ret;
}

static int afp_chmod(const char * path, mode_t mode) 
{
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	int ret;

	log_fuse_event(AFPFSD,LOG_DEBUG,
		"** chmod %s\n",path);
	ret=ml_chmod(volume,path,mode);

	switch (ret) {

	case -EPERM:
		LOG(AFPFSD,LOG_DEBUG,
			"You're not the owner of this file.\n");
		break;

	case -ENOSYS:
                LOG(AFPFSD,LOG_WARNING,"chmod unsupported or this mode is not possible with this server\n");
		break;
	case -EFAULT:
	LOG(AFPFSD,LOG_ERR,
	"You're mounting from a netatalk server, and I was trying to change "
	"permissions but you're setting some mode bits that aren't supported " 
	"by the server.  This is because this netatalk server is broken. \n"
	"This is because :\n"
	" - you haven't set -options=unix_priv in AppleVolumes.default\n"
	" - you haven't applied a patch which fixes chmod() to netatalk, or are using an \n"
	"   old version. See afpfs-ng docs.\n"
	" - maybe both\n"
	"It sucks, but I'm marking this volume as broken for 'extended' chmod modes.\n"
	"Allowed bits are: %o\n", AFP_CHMOD_ALLOWED_BITS_22);

		ret=0; /* Return anyway */
		break;
	}


	return ret;
}

static int afp_utime(const char * path, struct utimbuf * timebuf)
{

	int ret=0;
	unsigned int dirid;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	struct afp_file_info fp;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	int rc;

	if (volume_is_readonly(volume))
		return -EPERM;
	memset(&fp,0,sizeof(struct afp_file_info));

	fp.modification_date=timebuf->modtime;

	log_fuse_event(AFPFSD,LOG_DEBUG,
		"** utime\n");

	if (invalid_filename(volume->server,path)) 
		return -ENAMETOOLONG;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(volume,converted_path,basename,&dirid );

	if (is_dir(volume,dirid,basename)) {
		rc=afp_setdirparms(volume,
			dirid,basename, kFPModDateBit, &fp);
	} else {
		rc=afp_setfileparms(volume,
			dirid,basename, kFPModDateBit, &fp);
	}

	switch(rc) {
	case kFPNoErr:
		break;
	case kFPAccessDenied:
		return -EACCES;
	case kFPObjectNotFound:
		return -ENOENT;
	case kFPBitmapErr:
	case kFPMiscErr:
	case kFPObjectTypeErr:
	case kFPParamErr:
	default:
		break;

	}

	return -ret;
}


static void afp_destroy(void * ignore) 
{
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;

	if (volume->mounted!=AFP_VOLUME_UNMOUNTING) {
		LOG(AFPFSD,LOG_WARNING,"Skipping unmounting of this volume\n");
		return;
	}
	if ((!volume) || (volume->server)) return;

	/* Flush the cache, if we had one */

	/* We're just ignoring the results since there's nothing we could
	   do with them anyway.  */

	afp_unmount_volume(volume);

}

static int afp_symlink(const char * path1, const char * path2) 
{

	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	int ret;
	struct afp_file_info fp;
	uint64_t written;
	int rc;
	unsigned int dirid2;
	char basename2[AFP_MAX_PATH];
	char converted_path1[AFP_MAX_PATH];
	char converted_path2[AFP_MAX_PATH];

	if (volume->server->using_version->av_number<30) {
		/* No symlinks for AFP 2.x. */
		ret=ENOSYS;
		goto error;
	}
	/* Yes, you can create symlinks for AFP >=30.  Tested with 10.3.2 */

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path1,(char *) path1,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path2,(char *) path2,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(volume,converted_path2,basename2,&dirid2 );

	/* 1. create the file */
	rc=afp_createfile(volume,kFPHardCreate,dirid2,basename2);
	switch (rc) {
	case kFPAccessDenied:
		ret=EACCES;
		goto error;
	case kFPDiskFull:
		ret=ENOSPC;
		goto error;
	case kFPObjectExists:
		ret=EEXIST;
		goto error;
	case kFPObjectNotFound:
		ret=ENOENT;
		goto error;
	case kFPFileBusy:
	case kFPVolLocked:
		ret=EBUSY;
		goto error;
	case kFPNoErr:
		ret=0;
		break;
	default:
	case kFPParamErr:
	case kFPMiscErr:
		ret=EIO;
		goto error;
	}

	/* Open the fork */
	rc=afp_openfork(volume,0,
		dirid2,
		AFP_OPENFORK_ALLOWWRITE|AFP_OPENFORK_ALLOWREAD,
		basename2,&fp);
	switch (ret) {
	case kFPAccessDenied:
		ret=EACCES;
		goto error;
	case kFPObjectNotFound:
		ret=ENOENT;
		goto error;
	case kFPObjectLocked:
		ret=EROFS;
		goto error;
	case kFPObjectTypeErr:
		ret=EISDIR;
		goto error;
	case kFPParamErr:
		ret=EACCES;
		goto error;
	case kFPTooManyFilesOpen:
		ret=EMFILE;
		goto error;
	case kFPVolLocked:
	case kFPDenyConflict:
	case kFPMiscErr:
	case kFPBitmapErr:
	case -1:
		LOG(AFPFSD,LOG_WARNING,
			"Got some sort of internal error in afp_open\n");
		ret=EFAULT;
		goto error;
	case 0:
		ret=0;
		break;
	default:
		LOG(AFPFSD,LOG_WARNING,
			"Got some sort of other error in afp_open\n");
		ret=EFAULT;
		goto error;
	}


	/* Write the name of the file to it */

	rc=afp_writeext(volume,fp.forkid,0,strlen(converted_path1),
		converted_path1,&written);

	switch(afp_closefork(volume,fp.forkid)) {
	case kFPNoErr:
		break;
	default:
	case kFPParamErr:
	case kFPMiscErr:
		ret=EIO;
		goto error;
	}

	/* And now for the undocumented magic */
	memset(&fp.finderinfo,0,32);
	fp.finderinfo[0]='s';
	fp.finderinfo[1]='l';
	fp.finderinfo[2]='n';
	fp.finderinfo[3]='k';
	fp.finderinfo[4]='r';
	fp.finderinfo[5]='h';
	fp.finderinfo[6]='a';
	fp.finderinfo[7]='p';

	rc=afp_setfiledirparms(volume,dirid2,basename2,
		kFPFinderInfoBit, &fp);
	switch (rc) {
	case kFPAccessDenied:
		ret=EPERM;
		goto error;
	case kFPBitmapErr:
		/* This is the case where it isn't supported */
		LOG(AFPFSD,LOG_WARNING,"symlink creation unsupported\n");
		ret=ENOSYS;
		goto error;
	case kFPObjectNotFound:
		ret=ENOENT;
		goto error;
	case 0:
		ret=0;
		break;
	case kFPMiscErr:
	case kFPObjectTypeErr:
	case kFPParamErr:
	default:
		ret=EIO;
		goto error;
	}
error:
	return -ret;
};

static int afp_rename(const char * path_from, const char * path_to) 
{
	int ret,rc;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char basename_from[AFP_MAX_PATH];
	char basename_to[AFP_MAX_PATH];
	char converted_path_from[AFP_MAX_PATH];
	char converted_path_to[AFP_MAX_PATH];
	unsigned int dirid_from,dirid_to;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path_from,(char *) path_from,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path_to,(char *) path_to,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(volume, converted_path_from, basename_from, &dirid_from);
	get_dirid(volume, converted_path_to, basename_to, &dirid_to);

	if (is_dir(volume,dirid_to,converted_path_to)) {
		rc=afp_moveandrename_request(volume,
			dirid_from,dirid_to,
			basename_from,basename_to,basename_from);
	} else {
		rc=afp_moveandrename_request(volume,
			dirid_from,dirid_to,
			basename_from,NULL,basename_to);
	}
	switch(rc) {
	case kFPObjectLocked:
	case kFPAccessDenied:
		ret=EACCES;
		break;
	case kFPCantRename:
		ret=EROFS;
		break;
	case kFPObjectExists:
		/* First, remove the old file. */
		switch(afp_delete(volume,dirid_to,basename_to)) {

		case kFPAccessDenied:
			ret=EACCES;
			break;
		case kFPObjectLocked:
			ret=EBUSY;
			break;
		case kFPObjectNotFound:
			ret=ENOENT;
			break;
		case kFPVolLocked:
			ret=EACCES;
			break;
		case kFPDirNotEmpty:
			ret=ENOTEMPTY;
			break;
		case kFPObjectTypeErr:
		case kFPMiscErr:
		case kFPParamErr:
		case -1:
			ret=EINVAL;
			break;
		}
		/* Then, do the move again */
		switch(afp_moveandrename_request(volume,
			dirid_from,dirid_to,
			basename_from,NULL,basename_to)) {
		case kFPObjectLocked:
		case kFPAccessDenied:
			ret=EACCES;
			break;
		case kFPCantRename:
			ret=EROFS;
			break;
		case kFPObjectExists:
		case kFPObjectNotFound:
			ret=ENOENT;
			break;
		case kFPParamErr:
		case kFPMiscErr:
			ret=EIO;
		default:	
		case kFPNoErr:
			ret=0;
			break;
		}
		break;
	case kFPObjectNotFound:
		ret=ENOENT;
	case kFPNoErr:
		ret=0;
		break;
	default:	
	case kFPParamErr:
	case kFPMiscErr:
		ret=EIO;
	}
	return -ret;
}


#if FUSE_USE_VERSION < 26
static void *afp_init(void) {
#else 
static void *afp_init(void * o) {
#endif
	struct afp_volume * vol = global_volume;

	vol->private=(void *)((struct fuse_context *)(fuse_get_context()))->fuse;
	/* Trigger the daemon that we've started */
	if (vol->private) vol->mounted=1;
	pthread_cond_signal(&vol->startup_condition_cond);
	return (void *) vol;
}

static int afp_statfs(const char *path, struct statvfs *stat)
{
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	unsigned short flags;
int ret;

	memset(stat,0,sizeof(*stat));

	if (volume->server->using_version->av_number<30)
		flags = kFPVolBytesFreeBit | kFPVolBytesTotalBit ;
	else 
		flags = kFPVolExtBytesFreeBit | kFPVolExtBytesTotalBit | kFPVolBlockSizeBit;

	ret=afp_getvolparms(volume,flags);
	switch(ret) {
	case kFPNoErr:
		break;
	case kFPParamErr:
	case kFPMiscErr:
	default:
		return -EIO;
	}
	if (volume->stat.f_bsize==0) volume->stat.f_bsize=4096;
	stat->f_blocks=volume->stat.f_blocks / volume->stat.f_bsize;
	stat->f_bfree=volume->stat.f_bfree / volume->stat.f_bsize;
	stat->f_bsize=volume->stat.f_bsize;
	stat->f_frsize=volume->stat.f_bsize;
	stat->f_bavail=stat->f_bfree;
	stat->f_frsize=0;
	stat->f_files=0;
	stat->f_ffree=0;
	stat->f_favail=0;
	stat->f_fsid=0;
	stat->f_flag=0;
	stat->f_namemax=255;
	return 0;

}


static struct fuse_operations afp_oper = {
	.getattr	= afp_getattr,
	.open	= afp_open,
	.read	= afp_read,
	.readdir	= afp_readdir,
	.mkdir      = afp_mkdir,
	.readlink = afp_readlink,
	.rmdir	= afp_rmdir,
	.unlink = afp_unlink,
	.mknod  = afp_mknod,
	.write = afp_write,
	.release= afp_release,
	.chmod=afp_chmod,
	.symlink=afp_symlink,
	.chown=afp_chown,
	.truncate=afp_truncate,
	.rename=afp_rename,
	.utime=afp_utime,
	.destroy=afp_destroy,
	.init=afp_init,
	.statfs=afp_statfs,
};


int afp_register_fuse(int fuseargc, char *fuseargv[],struct afp_volume * vol)
{
	int ret;
	global_volume=vol;

#if FUSE_USE_VERSION < 26
	ret=fuse_main(fuseargc, fuseargv, &afp_oper);
#else
	ret=fuse_main(fuseargc, fuseargv, &afp_oper,(void *) vol);
#endif
	return ret;
}


