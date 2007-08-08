

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
#include <asm/fcntl.h>

#include <utime.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <syslog.h>
#include <signal.h>

#include "dsi.h"
#include "afp_protocol.h"
#include "utils.h"
#include "log.h"
#include "volinfo.h"
#include "did.h"
#include "resource.h"
#include "users.h"
#include "codepage.h"

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

/* get_directory_entry is used to abstract afp_getfiledirparms
   because in AFP<3.0 there is only afp_getfileparms and afp_getdirparms.
*/

static int get_directory_entry(struct afp_volume * volume,
	char * basename, 
	unsigned int dirid,
	unsigned int filebitmap, unsigned int dirbitmap,
	struct afp_file_info *p)

{
	int ret =afp_getfiledirparms(volume,dirid,
		filebitmap,dirbitmap,basename,p);
	return ret;
}

static int get_unixprivs(struct afp_volume * volume,
	unsigned int dirid, 
	const char * path, struct afp_file_info * fp) 
{
	
	switch (get_directory_entry(volume,(char *)path,
		dirid, kFPUnixPrivsBit,kFPUnixPrivsBit,fp)) {
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
	return 0;
}


static int set_unixprivs(struct afp_volume * volume,
	unsigned int dirid, 
	const char * basename, struct afp_file_info * fp) 

{
	int ret=0, rc;

	fp->unixprivs.ua_permissions=0;

	if (fp->isdir) {
		rc=afp_setdirparms(volume, dirid,basename,
			kFPUnixPrivsBit, fp);
	} else {


		rc=afp_setfiledirparms(volume,dirid,basename,
			kFPUnixPrivsBit, fp);
	}

	switch (rc) {
	case kFPAccessDenied:
		ret=EPERM;
		break;
	case kFPBitmapErr:
		/* This is the case where it isn't supported */
		LOG(AFPFSD,LOG_WARNING,"chmod unsupported\n");
		ret=ENOSYS;
		break;
	case kFPObjectNotFound:
		ret=ENOENT;
		break;
	case 0:
		ret=0;
		break;
	case kFPMiscErr:
	case kFPObjectTypeErr:
	case kFPParamErr:
	default:
		ret=EIO;
		break;
	}
	return -ret;
}

static int map_servertohost(struct afp_server * server, 
	unsigned int serveruid, unsigned int * hostuid,
	unsigned int servergid, unsigned int * hostgid)
{
	if (1) {
		/* This is normally only done for server versions < 30, but 
                 * since name translation is currently horked, we're 
                 * enabling it always. */
		*hostuid=getuid();
		*hostgid=getgid();

	} else {
		if (user_findbyserverid(server,1, /* Is UID */
			serveruid,hostuid)) return -1;
		if (user_findbyserverid(server,0, /* Is GID */
			serveruid,hostgid)) return -1;
	}

	return 0;
}

/*
 * set_uidgid()
 *
 * This sets the userid and groupid in an afp_file_info struct using the 
 * appropriate translation.
 *
 * It only sets them if the translation can be done.
 *
 */

static int set_uidgid(struct afp_server * server, 
	struct afp_file_info * fp, uid_t uid, gid_t gid)
{

	unsigned int newid;
	int ret=0;

	/* If we ever have to do uid/gid translation, it'd go here */

	if (user_findbyhostid(server,1 /* is UID */,uid,&newid)==0) 
		fp->unixprivs.uid=newid;
	else
		ret=-1;

	if (user_findbyhostid(server,0 /* is GID */,gid,&newid)==0)
		fp->unixprivs.uid=newid;
	else
		ret=-1;

	return ret;
}

static int afp_getattr(const char *path, struct stat *stbuf)
{
	struct afp_file_info fp;
	unsigned int dirid;
	char * c;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	int rc;
	char resource;
	unsigned int filebitmap, dirbitmap;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** getattr of %s\n",path);

	/* Oddly, we sometimes get <dir1>/<dir2>/(null) for the path */

	if (!path) return -EIO;

	if ((c=strstr(path,"(null)"))) {
		/* We should fix this to make sure it is at the end */
		if (c>path) *(c-1)='\0';
	}

	memset(stbuf, 0, sizeof(struct stat));

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_volinfo(converted_path)) 
		return volinfo_getattr(converted_path,stbuf);

	if (is_apple(converted_path)) 
	{
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
	if (map_servertohost(volume->server,
		fp.unixprivs.uid,&stbuf->st_uid,
		fp.unixprivs.gid,&stbuf->st_gid)) return -EIO;

	stbuf->st_ctim.tv_sec=fp.creation_date;
	stbuf->st_mtim.tv_sec=fp.modification_date;

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
		converted_path,path,AFP_MAX_PATH)) {
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
		buf,link_path,AFP_MAX_PATH);

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

	if (apple_translate(volume,path))
		return 0;

	if (is_apple(path)) 
		return 0;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

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

	if (is_apple(path))
		return 0;

	if (apple_translate(volume,path))
		return 0;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

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
	unsigned int dirid=0;
	struct afp_file_info * filebase = NULL, * p, *prev;
	unsigned short reqcount=20;  /* Get them in batches of 20 */
	unsigned long startindex=1;
	int rc=0, ret=0, exit=0;
	unsigned int filebitmap, dirbitmap;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	int resource=0;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	char converted_name[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,"*** readdir of %s\n",path);

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_volinfo(converted_path))
		return volinfo_readdir(converted_path,buf,filler,offset,fi);

	if (volume->options & VOLUME_OPTION_APPLEDOUBLE) {
		resource=apple_translate(volume,converted_path);
		switch(resource) {
			case AFP_RESOURCE_TYPE_PARENT1:
				break;
			case AFP_RESOURCE_TYPE_PARENT2:
				filler(buf,"comment",NULL,0);
				filler(buf,"finderinfo",NULL,0);
				filler(buf,"rsrc",NULL,0);
				return 0;
				break;
			default:
				break;
/*
			filler(buf, ".AppleDouble", NULL, 0);
*/
		}
	}

	if (invalid_filename(volume->server,converted_path)) 
		return -ENAMETOOLONG;

	get_dirid(volume, converted_path, basename, &dirid);

	/* We need to handle length bits differently for AFP < 3.0 */

	filebitmap=kFPAttributeBit | kFPParentDirIDBit |
		kFPCreateDateBit | kFPModDateBit |
		kFPBackupDateBit|
		kFPNodeIDBit | 
		kFPUnixPrivsBit;
	dirbitmap=kFPAttributeBit | kFPParentDirIDBit |
		kFPCreateDateBit | kFPModDateBit |
		kFPBackupDateBit|
		kFPNodeIDBit | kFPOffspringCountBit|
		kFPOwnerIDBit|kFPGroupIDBit|
		kFPUnixPrivsBit;
	if (volume->attributes & kSupportsUTF8Names ) {
		dirbitmap|=kFPUTF8NameBit;
		filebitmap|=kFPUTF8NameBit;
	} else {
		dirbitmap|=kFPLongNameBit| kFPShortNameBit;
		filebitmap|=kFPLongNameBit| kFPShortNameBit;
	}
	if (volume->server->using_version->av_number<30)
		filebitmap|=kFPDataForkLenBit;
	else 
		filebitmap|=kFPExtDataForkLenBit;

	while (!exit) {

		/* this function will allocate and generate a linked list 
		   of files */
		rc = afp_enumerateext2_request(volume,dirid,
			filebitmap, dirbitmap,reqcount,
			startindex,basename,&filebase);
		switch(rc) {
		case -1:
			ret=EIO;
			goto error;
		case 0:
			if (!filebase) {
				LOG(AFPFSD,LOG_DEBUG,
				"Could not get the filebase I just looked for.  Weird.\n");
				ret=ENOENT;
				goto error;
			}
	
			for (p=filebase; p; ) {
				/* Convert all the names back to precomposed */
				convert_path_to_unix(
					volume->server->path_encoding, 
					converted_name,p->name, AFP_MAX_PATH);
				filler(buf,converted_name,NULL,0);
				startindex++;
				prev=p;
				p=p->next;
				free(prev);  /* free up the files */
			}
			if (!filebase) exit++;
			break;
		case kFPAccessDenied:
			ret=EACCES;
			goto error;
		case kFPDirNotFound:
			ret=ENOENT;
			exit++;
			break;
		case kFPObjectNotFound:
			goto done;
		case kFPBitmapErr:
		case kFPMiscErr:
		case kFPObjectTypeErr:
		case kFPParamErr:
			ret=EIO;
			goto error;
		}
	}

done:

    return 0;
error:
	return -ret;
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

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	/* If it is a resource fork, create the main one */
	resource=apple_translate(volume,converted_path);
 
	if (invalid_filename(volume->server,converted_path)) 
		return -ENAMETOOLONG;

	get_dirid(volume, converted_path, basename, &dirid);

	rc=afp_createfile(volume,kFPSoftCreate, dirid,basename);
	switch(rc) {
	case kFPAccessDenied:
		ret=EACCES;
		break;
	case kFPDiskFull:
		ret=ENOSPC;
		break;
	case kFPObjectExists:
		ret=EEXIST;
		break;
	case kFPObjectNotFound:
		ret=ENOENT;
		break;
	case kFPFileBusy:
	case kFPVolLocked:
		ret=EBUSY;
		break;
	case kFPNoErr:
		ret=0;
		break;
	default:
	case kFPParamErr:
	case kFPMiscErr:
		ret=EIO;
	}

	if (ret) return -ret;


	/* Figure out the privs of the file we just created */
	if ((ret=get_unixprivs(volume,
		dirid,basename, &fp)))
		return rc;

	if (ret) return -ret;


	fp.unixprivs.ua_permissions=0;
	fp.unixprivs.permissions=mode;
	fp.isdir=0;  /* Anything you make with mknod is a file */
	set_uidgid(volume->server,&fp,context->uid, context->gid);
	
	rc=set_unixprivs(volume, dirid, basename, &fp);

	switch(rc) {
	case kFPAccessDenied:
		ret=EPERM;
		goto error;
	case kFPObjectNotFound:
		ret=ENOENT;
		goto error;
	case 0:
		ret=0;
		break;
	case kFPBitmapErr:
	case kFPMiscErr:
	case kFPObjectTypeErr:
	case kFPParamErr:
	default:
		ret=EIO;
		goto error;
	}

error:
	return -ret;
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

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}
 
	if (invalid_filename(volume->server,converted_path)) 
		return -ENAMETOOLONG;

	/* The logic here is that if we don't have an fp anymore, then the
	   fork must already be closed. */
	if (fp) {
		if (fp->icon) {
			free(fp->icon);
		}
		if (fp->resource) {
			free((void *) fi->fh);
			return 0;
		}

		switch(afp_flushfork(volume,fp->forkid)) {
		case kFPNoErr:
			break;
		default:
		case kFPParamErr:
		case kFPMiscErr:
			ret=EIO;
			goto error;
		}
		switch(afp_closefork(volume,fp->forkid)) {
		case kFPNoErr:
			break;
		default:
		case kFPParamErr:
		case kFPMiscErr:
			ret=EIO;
			goto error;
			break;

		}
	} else {
		ret=EBADF;
	}
		
error:
	free((void *) fi->fh);
	return ret;
}

static int afp_open(const char *path, struct fuse_file_info *fi)
{

	struct afp_file_info * fp ;
	int ret, dsi_ret,rc;
	unsigned char flags = AFP_OPENFORK_ALLOWREAD;
	int create_file=0;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	char resource=0;
	unsigned int dirid;
	char converted_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,
		"*** Opening path %s\n",path);

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (invalid_filename(volume->server,converted_path)) {
		return -ENAMETOOLONG;
	}

	if ((fp=malloc(sizeof(*fp)))==NULL) {
		return -1;
	}
	fi->fh=(void *) fp;
	memset(fp,0,sizeof(*fp));

	if (is_volinfo(converted_path)) {
		if ((ret=volinfo_open(converted_path,fi))<0) {
			return ret;
		}
		goto out;
	}

	get_dirid(volume,converted_path,fp->basename,&dirid);

	fp->did=dirid;
	
	switch ((resource=apple_translate(volume,converted_path))) {
	case AFP_RESOURCE_TYPE_FINDERINFO:
		goto out;
	case AFP_RESOURCE_TYPE_COMMENT:
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
		goto out;
	}


	if (fi->flags & O_RDONLY) flags|=AFP_OPENFORK_ALLOWREAD;
	if (fi->flags & O_WRONLY) flags|=AFP_OPENFORK_ALLOWWRITE;
	if (fi->flags & O_RDWR) flags |= (AFP_OPENFORK_ALLOWREAD | AFP_OPENFORK_ALLOWWRITE);

	if ((flags&AFP_OPENFORK_ALLOWWRITE) & 
		(volume_is_readonly(volume))) {
		ret=EPERM;
		goto error;
	}

	/*
	   O_NOBLOCK - todo: it is unclear how to this in fuse.
	*/

	/* The following flags don't need any attention here:
	   O_ASYNC - not relevant for files
	   O_APPEND
	   O_NOATIME - we have no way to handle this anyway
	*/


	/*this will be used later for caching*/
	fp->sync=(fi->flags & (O_SYNC | O_DIRECT));  

	/* See if we need to create the file  */
	if (flags & AFP_OPENFORK_ALLOWWRITE) {
		if (create_file) {
			/* Create the file */
			if (fi->flags & O_EXCL) {
				ret=EEXIST;
				goto error;
			}
			rc=afp_createfile(volume,kFPSoftCreate,
				dirid, fp->basename);
		} 
	}

	if ((fi->flags & O_LARGEFILE) && 
		(volume->server->using_version->av_number<30)) {
		switch(get_directory_entry(volume,fp->basename,dirid,
			kFPParentDirIDBit|kFPNodeIDBit|
			(resource ? kFPRsrcForkLenBit : kFPDataForkLenBit),
				0,fp)) {
		case kFPAccessDenied:
			ret=EACCES;
			goto error;
		case kFPObjectNotFound:
			ret=ENOENT;
			goto error;
		case kFPNoErr:
			break;
		case kFPBitmapErr:
		case kFPMiscErr:
		case kFPParamErr:
		default:
			ret=EIO;
			goto error;
		}

		if ((resource ? (fp->resourcesize>=LARGEST_AFP2_FILE_SIZE-1) :
		( fp->size>=LARGEST_AFP2_FILE_SIZE-1))) {
	/* According to p.30, if the server doesn't support >4GB files
	   and the file being opened is >4GB, then resourcesize or size
	   will return 4GB.  How can it return 4GB in 32 its?  I 
	   suspect it actually returns 4GB-1.
	*/
			ret=EOVERFLOW;
			goto error;
		}
	}

	dsi_ret=afp_openfork(volume,resource,dirid,
		flags,fp->basename,fp);

	switch (dsi_ret) {
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

	if ((fi->flags & O_TRUNC) && (!create_file)) {
		/* This is the case where we want to truncate the 
		   the file and it already exists. */
		switch(afp_setforkparms(volume,fp->forkid,
			(resource ? kFPRsrcForkLenBit : kFPDataForkLenBit),0)) {
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
		if (ret) goto error;
	}

out:
	fp->resource=resource;
	return 0;

error:
	free(fp);
	return -ret;
}

static int handle_unlocking(struct afp_volume * volume,unsigned short forkid, 
	uint64_t offset, uint64_t sizetorequest)
{
	uint64_t generated_offset;
	int rc;
	rc=afp_byterangelockext(volume,ByteRangeLock_Unlock,
			forkid,offset, sizetorequest,&generated_offset);
	switch(rc) {
		case kFPNoErr:
			break;
		case kFPMiscErr:
		case kFPParamErr:
		case kFPRangeNotLocked:
		default:
			return -1;
	}
	return 0;
}

static int handle_locking(struct afp_volume * volume,unsigned short forkid, 
	uint64_t offset, uint64_t sizetorequest)
{

#define MAX_LOCKTRYCOUNT 10

	int rc=0;
	int try=0;
	uint64_t generated_offset;

	while (try<MAX_LOCKTRYCOUNT) {
		try++;
		rc=afp_byterangelockext(volume,ByteRangeLock_Lock,
			forkid,offset, sizetorequest,&generated_offset);
		switch(rc) {
		case kFPNoErr:
			goto done;
		case kFPNoMoreLocks: /* Max num of locks on server */
		case kFPLockErr:  /*Some or all of the requested range is locked
				    by another user. */

			sleep(1);
			break;
		default:
			return -1;
		}
	}
done:
	return 0;
}

static void update_time(unsigned int * newtime)
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	*newtime=tv.tv_sec;
}


int afp_write(const char * path, const char *data, size_t size, off_t offset,
                  struct fuse_file_info *fi)
{

	struct afp_file_info *fp = (struct afp_file_info *) fi->fh;
	int ret,err=0;
	int totalwritten = 0;
	uint64_t sizetowrite, ignored;
	unsigned char flags = 0;
	struct fuse_context * context = fuse_get_context();
	struct afp_volume * volume=(void *) context->private_data;
	unsigned int max_packet_size=volume->server->tx_quantum;
	off_t o=0;
	char converted_path[AFP_MAX_PATH];

/* TODO:
   - handle nonblocking IO correctly
   - handle afp_writeext for AFP 2.2, return EFBIG if the size is too large
*/
	log_fuse_event(AFPFSD,LOG_DEBUG,
		"*** write of from %llu for %llu\n",
		(unsigned long long) offset,(unsigned long long) size);
	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	apple_translate(volume,converted_path);	


	if (is_volinfo(converted_path))
		return volinfo_write(converted_path,data,size,offset,fi);

	switch (fp->resource) {
	case AFP_RESOURCE_TYPE_FINDERINFO: 
		memcpy(fp->finderinfo,data,32);
		switch(afp_setfileparms(volume,
				fp->did,fp->basename,
				kFPFinderInfoBit, fp)) {
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
		totalwritten=size;
		break;
	case AFP_RESOURCE_TYPE_COMMENT: {
		uint64_t size;
		switch(afp_addcomment(volume, fp->did,fp->basename,
			(char *)data,&size)) {
		case kFPAccessDenied:
			return -EACCES;
		case kFPObjectNotFound:
			return -ENOENT;
		case kFPNoErr:
			return size;
		case kFPMiscErr:
		default:
			return -EIO;
		}
		totalwritten=size;
		break;
	}
	default:
		break;
	}

	/* Set the time and perms */

	/* There's no way to do this in AFP < 3.0 */
	if (volume->server->using_version->av_number >= 30) {
		
		flags|=kFPUnixPrivsBit;
		set_uidgid(volume->server,fp,context->uid, context->gid);
		fp->unixprivs.permissions=0100644;
	};

	
	update_time(&fp->modification_date);
	flags|=kFPModDateBit;

	switch(afp_setfileparms(volume,
			fp->did, fp->basename,
			flags, fp)) {
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

	if (!fp) return -EBADF;

	/* Get a lock */
	if (handle_locking(volume, fp->forkid,offset,size)) {
		/* There was an irrecoverable error when locking */
		ret=EBUSY;
		goto error;
	}

	ret=0;
	while (totalwritten < size) {
		sizetowrite=max_packet_size;
		if ((size-totalwritten)<max_packet_size)
			sizetowrite=size-totalwritten;
		ret=afp_writeext(volume, fp->forkid,
			offset+o,sizetowrite,
			1024,(char *) data+o,&ignored);
		ret=0;
		totalwritten+=sizetowrite;
		switch(ret) {
		case kFPAccessDenied:
			err=EACCES;
			goto error;
		case kFPDiskFull:
			err=ENOSPC;
			goto error;
		case kFPLockErr:
		case kFPMiscErr:
		case kFPParamErr:
			err=EINVAL;
			goto error;
		}
		o+=sizetowrite;
	}
	if (handle_unlocking(volume, fp->forkid,offset,size)) {
		/* Somehow, we couldn't unlock the range. */
		ret=EIO;
		goto error;
	}
	return totalwritten;

error:
	return -err;


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
		converted_path,path,AFP_MAX_PATH)) {
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
	int bytesleft=size;
	int totalsize=0;
	int ret=0;
	int rc;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	unsigned int bufsize=min(volume->server->rx_quantum,size);
	char converted_path[AFP_MAX_PATH];
	struct afp_rx_buffer buffer;

	if (!fi || !fi->fh) 
		return -EBADF;
	fp=(void *) fi->fh;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_volinfo(converted_path)) {
		ret=volinfo_read(converted_path,buf,size,offset,fi);
		return ret;
	}

	if (fp->resource) 
		apple_translate(volume,converted_path);
	switch(fp->resource) {
	case AFP_RESOURCE_TYPE_FINDERINFO:
	{
		struct afp_file_info fp2;
		rc=get_directory_entry(volume,fp->basename,
			fp->did, kFPFinderInfoBit,kFPFinderInfoBit ,&fp2);
		switch (rc) {
		case kFPAccessDenied:
			ret=EACCES;
			goto error;
		case kFPObjectNotFound:
			ret=ENOENT;
			goto error;
		case kFPNoErr:
			break;
		case kFPBitmapErr:
		case kFPMiscErr:
		case kFPParamErr:
		default:
			ret=EIO;
			goto error;
		}
		memcpy(buf,fp2.finderinfo,32);
		return 32;
	}
	case AFP_RESOURCE_TYPE_COMMENT:
	{
        	struct afp_comment comment;
		comment.size=0;
		comment.maxsize=size;
		comment.data=buf;
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
		switch(afp_getcomment(volume,fp->did, fp->basename,&comment)) {
		case kFPAccessDenied:
			return -EACCES;
		case kFPMiscErr:
		case kFPParamErr:
			return -EIO;
		case kFPItemNotFound:
		case kFPObjectNotFound:
			return -ENOENT;
		case kFPNoErr:
		default:
			break;
		}
		return comment.size;
	}
	}

	buffer.data = buf;
	buffer.maxsize=bufsize;
	buffer.size=0;
	/* Lock the range */
	if (handle_locking(volume, fp->forkid,offset,size)) {
		/* There was an irrecoverable error when locking */
		ret=EBUSY;
		goto error;
	}

	rc=afp_readext(volume, fp->forkid,offset,size,&buffer);
	if (handle_unlocking(volume, fp->forkid,offset,size)) {
		/* Somehow, we couldn't unlock the range. */
		ret=EIO;
		goto error;
	}
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

	bytesleft-=buffer.size;
	totalsize+=buffer.size;
	return totalsize;
error:
	return -ret;

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
		converted_path,path,AFP_MAX_PATH)) {
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

	set_uidgid(volume->server,&fp,uid,gid);
	rc=set_unixprivs(volume, dirid, basename, &fp);

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
		converted_path,path,AFP_MAX_PATH)) {
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

	/* For truncating to 0, you can just use kFPDataForkLenBit, not
	   kFPExtDataForkLenBit (netatalk gives you an error).  */

	ret=afp_setforkparms(volume,forkid,kFPDataForkLenBit,0);
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

	afp_closefork(volume,forkid);

	return -ret;
}

static int afp_chmod(const char * path, mode_t mode) 
{
/*
chmod has an interesting story to it.  

It is known to work with Darwin 10.3.9 (AFP 3.1) and  10.4.2 (AFP 3.2).

chmod will not work properly in the following situations:

- AFP 2.2, this needs some more verification but I don't see how it is possible

- netatalk 2.0.3 and probably earlier:

  . netatalk will only enable it at all if you have "options=upriv" 
    set for that volume.

  . netatalk will never be able to chmod the execute bit and some others on 
    files; this is hard coded in unix.c's setfilemode() in 2.0.3.  It's like
    it has 2.2 behaviour even though it is trying to speak 3.1.

  . The only bits allowed are
        S_IRUSR |S_IWUSR | S_IRGRP | S_IWGRP |S_IROTH | S_IWOTH;
    There's probably a reason for this, I don't know what it is.

  . afpfs-ng's behaviour's the same as the Darwin client.

The right way to see if a volume supports chmod is to check the attributes
found with getvolparm or volopen, then to test chmod the first time.

*/
#define ALLOWED_BITS_22 \
	(S_IRUSR |S_IWUSR | S_IRGRP | S_IWGRP |S_IROTH | S_IWOTH | S_IFREG )
#define TOCHECK_BITS \
	(S_IRUSR |S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | \
	 S_IROTH | S_IWOTH | S_IXOTH | S_IFREG )

	int ret=0,rc,rc2;
	struct afp_file_info fp,fp2;
	struct afp_volume * volume=
		(struct afp_volume *)
		((struct fuse_context *)(fuse_get_context()))->private_data;
	unsigned int dirid;
	char basename[AFP_MAX_PATH];
	unsigned int serveruid, servergid;
	char converted_path[AFP_MAX_PATH];

	log_fuse_event(AFPFSD,LOG_DEBUG,
		"** chmod %s\n",path);
	if (volume_is_readonly(volume))
		return -EPERM;
	if (invalid_filename(volume->server,path)) 
		return -ENAMETOOLONG;

	/* There's no way to do this in AFP < 3.0 */
	if ((volume->server->using_version->av_number < 30) ||
		(~ volume->attributes & kSupportsUnixPrivs)) {
		return -ENOSYS;
	};

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(volume,converted_path,basename,&dirid );

	if ((rc=get_unixprivs(volume,
		dirid,basename, &fp))) 
		return rc;

	mode&=(~S_IFDIR);

	/* Don't bother updating it if it's already the same */
	if ((fp.unixprivs.permissions&(~S_IFDIR))==mode)
		return 0;

	/* If this is netatalk and chmod is broken, check the mode */
	/* This is where we'd do 2.x checking also */
	if ((volume->server->server_type==AFPFS_SERVER_TYPE_NETATALK) && 
	 (volume->extra_flags & VOLUME_EXTRA_FLAGS_VOL_CHMOD_KNOWN) &&
	 (volume->extra_flags & VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN)) {
		if (mode & ~(ALLOWED_BITS_22)) {
			LOG(AFPFSD,LOG_DEBUG,
				"You've set some bit in chmod of 0%o that I can't handle\n",mode);
		}
	}

	/* Check to make sure that we can; some servers (at least netatalk)
	   don't report an error when you try to setfileparm when you don't
	   own the file.  */
	/* Todo: do proper uid translation */

	user_findbyhostid(volume->server,1,getuid(),&serveruid);
	user_findbyhostid(volume->server,0,getgid(),&servergid);

	if ((fp.unixprivs.gid!=servergid) && (fp.unixprivs.uid!=serveruid)) {
		LOG(AFPFSD,LOG_DEBUG,
			"You're not the owner of this file.\n");
		return -EPERM;
	}
	
	fp.unixprivs.permissions=mode;

	rc=set_unixprivs(volume, dirid,basename, &fp);

	/* If it is netatalk, check to see if that worked.  If not, 
	   never try this bitset again. */
	if ((mode & ~(ALLOWED_BITS_22)) && 
	 	(!(volume->extra_flags & VOLUME_EXTRA_FLAGS_VOL_CHMOD_KNOWN)) &&
		(volume->server->server_type==AFPFS_SERVER_TYPE_NETATALK))  
	{
		if ((rc2=get_unixprivs(volume,
			dirid, basename, &fp2))) 
			return rc2;
		volume->extra_flags|=VOLUME_EXTRA_FLAGS_VOL_CHMOD_KNOWN;
		if ((fp2.unixprivs.permissions&TOCHECK_BITS)!=
			(fp.unixprivs.permissions&TOCHECK_BITS)) {
			volume->extra_flags&=~VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN;
		} else {
			volume->extra_flags|=VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN;
		LOG(AFPFSD,LOG_ERR,
			"You're running netatalk with a broken chmod(). This is because :\n"
			" - you haven't set -options=unix_priv in AppleVolumes.default\n"
			" - you haven't applied a patch which fixes chmod().  See afpfs-ng docs.\n"
			" - maybe both\n"
			"It sucks, but I'm marking this volume as broken for extended chmod modes.\n");
		return 0;  /* And yes, we just return no error anyway. */
		}
	}


	return -ret;
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
		converted_path,path,AFP_MAX_PATH)) {
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
		converted_path1,path1,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path2,path2,AFP_MAX_PATH)) {
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
		strlen(converted_path1),converted_path1,&written);

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
		converted_path_from,path_from,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path_to,path_to,AFP_MAX_PATH)) {
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

	vol->fuse=((struct fuse_context *)(fuse_get_context()))->fuse;
	/* Trigger the daemon that we've started */
	if (vol->fuse) vol->mounted=1;
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
	global_volume=vol;

#if FUSE_USE_VERSION < 26
	return fuse_main(fuseargc, fuseargv, &afp_oper);
#else
	return fuse_main(fuseargc, fuseargv, &afp_oper,(void *) vol);
#endif
}


