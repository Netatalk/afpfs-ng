

/*
    midlevel.c: some funtions to abstract some of the common functions 

    Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/


#include "afp.h"

#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#ifdef __linux__
#include <asm/fcntl.h>
#else
#include <fcntl.h>
#endif


#include "users.h"
#include "did.h"
#include "resource.h"
#include "utils.h"
#include "volinfo.h"
#include "codepage.h"
#include "midlevel.h"


#define min(a,b) (((a)<(b)) ? (a) : (b))

/* get_directory_entry is used to abstract afp_getfiledirparms
 * because in AFP<3.0 there is only afp_getfileparms and afp_getdirparms.
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


void add_file(struct afp_file_info ** base, const char *filename)
{
	struct afp_file_info * t,*new_file;

	new_file=malloc(sizeof(*new_file));
	bcopy(filename,new_file->name,AFP_MAX_PATH);
	new_file->next=NULL;

	if (*base==NULL) {
		*base=new_file;
	} else {
		for (t=*base;t->next;t=t->next);
		t->next=new_file;
	}

}


static int handle_unlocking(struct afp_volume * volume,unsigned short forkid,
	uint64_t offset, uint64_t sizetorequest)
{
	uint64_t generated_offset;
	int rc;

	if (volume->server->using_version->av_number < 30) 
		rc=afp_byterangelock(volume,ByteRangeLock_Unlock,
				forkid,offset, sizetorequest,&generated_offset);
	else 
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
		if (volume->server->using_version->av_number < 30) 
			rc=afp_byterangelock(volume,ByteRangeLock_Lock,
				forkid,offset, sizetorequest,&generated_offset);
		else 
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



/*
 * set_uidgid()
 *
 * This sets the userid and groupid in an afp_file_info struct using the 
 * appropriate translation.  You should pass it the host's version of the
 * uid and gid.
 *
 */

static int set_uidgid(struct afp_volume * volume, 
	struct afp_file_info * fp, uid_t uid, gid_t gid)
{

	unsigned int newuid=uid;
	unsigned int newgid=gid;

	translate_uidgid_to_server(volume,&newuid,&newgid);

	fp->unixprivs.uid=newuid;
	fp->unixprivs.gid=newgid;

	return 0;
}

static void update_time(unsigned int * newtime)
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	*newtime=tv.tv_sec;
}

int ml_open(struct afp_volume * volume, const char *path, int flags, 
	struct afp_file_info **newfp)
{

/* FIXME:  doesn't handle create properly */

	struct afp_file_info * fp ;
	int ret, dsi_ret,rc;
	int create_file=0;
	char resource=0;
	unsigned int dirid;
	char converted_path[AFP_MAX_PATH];
	unsigned char aflags = AFP_OPENFORK_ALLOWREAD;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (invalid_filename(volume->server,converted_path)) {
		return -ENAMETOOLONG;
	}

	if ((fp=malloc(sizeof(*fp)))==NULL) {
		return -1;
	}
	*newfp=fp;

	memset(fp,0,sizeof(*fp));

	if (is_volinfo(converted_path)) {
		if ((ret=volinfo_open(volume,converted_path))<0) {
			return ret;
		}
		goto out;
	}

	if (get_dirid(volume,converted_path,fp->basename,&dirid)<0)
		return -ENOENT;

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

	if (flags & O_RDONLY) aflags|=AFP_OPENFORK_ALLOWREAD;
	if (flags & O_WRONLY) aflags|=AFP_OPENFORK_ALLOWWRITE;        
	if (flags & O_RDWR) 
		aflags |= (AFP_OPENFORK_ALLOWREAD | AFP_OPENFORK_ALLOWWRITE);


	if ((aflags&AFP_OPENFORK_ALLOWWRITE) & 
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
	fp->sync=(flags & (O_SYNC | O_DIRECT));  

	/* See if we need to create the file  */
	if (aflags & AFP_OPENFORK_ALLOWWRITE) {
		if (create_file) {
			/* Create the file */
			if (flags & O_EXCL) {
				ret=EEXIST;
				goto error;
			}
			rc=afp_createfile(volume,kFPSoftCreate,
				dirid, fp->basename);
		} 
	}

	if (
#ifdef __linux__
		(flags & O_LARGEFILE) && 
#endif
		(volume->server->using_version->av_number<30)) 
	{
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


try_again:
	dsi_ret=afp_openfork(volume,resource,dirid,
		aflags,fp->basename,fp);

	switch (dsi_ret) {
	case kFPAccessDenied:
		ret=EACCES;
		goto error;
	case kFPObjectNotFound:
		if ((flags & O_CREAT) && 
			(ml_creat(volume,path,0644)==0)) {
				goto try_again;
		} else {
			ret=ENOENT;
			goto error;
		}
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
		ret=EFAULT;
		goto error;
	case 0:
		ret=0;
		break;
	default:
		ret=EFAULT;
		goto error;
	}

	if ((flags & O_TRUNC) && (!create_file)) {

		/* This is the case where we want to truncate the 
		   the file and it already exists. */
		if ((ret=zero_file(volume,fp->forkid,resource)))
			goto error;
	}


out:
	fp->resource=resource;
	return 0;

error:
	free(fp);
	return -ret;
}



int ml_creat(struct afp_volume * volume, const char *path, mode_t mode)
{
	int ret=0;
	char resource;
	char basename[AFP_MAX_PATH];
	unsigned int dirid;
	struct afp_file_info fp;
	int rc;
	char converted_path[AFP_MAX_PATH];

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
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

	if (fp.unixprivs.permissions==mode)
	return 0;


	fp.unixprivs.ua_permissions=0;
	fp.unixprivs.permissions=mode;
	fp.isdir=0;  /* Anything you make with mknod is a file */
	/* note that we're not monkeying with the ownership here */
	
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



int ml_readdir(struct afp_volume * volume, 
	const char *path, 
	struct afp_file_info **base)
{
	struct afp_file_info * filebase = NULL, * p, *prev;
	unsigned short reqcount=20;  /* Get them in batches of 20 */
	unsigned long startindex=1;
	int rc=0, ret=0, exit=0;
	unsigned int filebitmap, dirbitmap;
	int resource=AFP_RESOURCE_TYPE_NONE;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	char converted_name[AFP_MAX_PATH];
	unsigned int dirid;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_volinfo(converted_path))
		return volinfo_readdir(converted_path,base);

	if (volume->options & VOLUME_OPTION_APPLEDOUBLE) {
		resource=apple_translate(volume,converted_path);
		if (is_double_apple(converted_path))
			return -ENOENT;
		switch(resource) {
			case AFP_RESOURCE_TYPE_PARENT1:
				break;
			case AFP_RESOURCE_TYPE_PARENT2:
				add_file(base,"comment");
				add_file(base,"finderinfo");
				add_file(base,"rsrc");
				return 0;
				break;
			default:
				break;
		}
	}

	if (invalid_filename(volume->server,converted_path)) 
		return -ENAMETOOLONG;

	if (get_dirid(volume, converted_path, basename, &dirid)<0)
		return -ENOENT;

	/* We need to handle length bits differently for AFP < 3.0 */

	filebitmap=kFPAttributeBit | kFPParentDirIDBit |
		kFPCreateDateBit | kFPModDateBit |
		kFPBackupDateBit|
		kFPNodeIDBit;
	dirbitmap=kFPAttributeBit | kFPParentDirIDBit |
		kFPCreateDateBit | kFPModDateBit |
		kFPBackupDateBit|
		kFPNodeIDBit | kFPOffspringCountBit|
		kFPOwnerIDBit|kFPGroupIDBit;

	if (volume->attributes &kSupportsUnixPrivs) {
		dirbitmap|=kFPUnixPrivsBit;
		filebitmap|=kFPUnixPrivsBit;
	}


	if (volume->attributes & kSupportsUTF8Names ) {
		dirbitmap|=kFPUTF8NameBit;
		filebitmap|=kFPUTF8NameBit;
	} else {
		dirbitmap|=kFPLongNameBit| kFPShortNameBit;
		filebitmap|=kFPLongNameBit| kFPShortNameBit;
	}
	if (volume->server->using_version->av_number<30) {
		filebitmap|=kFPDataForkLenBit;
	} else {
		filebitmap|=kFPExtDataForkLenBit;
	}

	while (!exit) {

/* FIXME: check AFP version */
		/* this function will allocate and generate a linked list 
		   of files */
		if (volume->server->using_version->av_number<30) {
			rc = afp_enumerate(volume,dirid,
				filebitmap, dirbitmap,reqcount,
				startindex,basename,&filebase);
		} else {
			rc = afp_enumerateext2(volume,dirid,
				filebitmap, dirbitmap,reqcount,
				startindex,basename,&filebase);
		}
		switch(rc) {
		case -1:
			ret=EIO;
			goto error;
		case 0:
			if (!filebase) {
				printf(
				"Could not get the filebase I just looked for.  Weird.\n");
				ret=ENOENT;
				goto error;
			}

#ifdef FIXME
this is really inefficient since we have to make a copy of everything.
#endif
	
			for (p=filebase; p; ) {
				/* Convert all the names back to precomposed */
				convert_path_to_unix(
					volume->server->path_encoding, 
					converted_name,p->name, AFP_MAX_PATH);
				if ((resource==AFP_RESOURCE_TYPE_NONE) ||
					(p->isdir==0))
					add_file(base,converted_name);
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
		case kFPCallNotSupported:
			ret=EIO;
			goto error;
		}
	}

done:

    return 0;
error:
	return -ret;
}

int ml_read(struct afp_volume * volume, const char *path, 
	char *buf, size_t size, off_t offset,
	struct afp_file_info *fp, int * eof)
{
	int bytesleft=size;
	int totalsize=0;
	int ret=0;
	int rc;
	unsigned int bufsize=min(volume->server->rx_quantum,size);
	char converted_path[AFP_MAX_PATH];
	struct afp_rx_buffer buffer;

	*eof=0;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_volinfo(converted_path)) {
		ret=volinfo_read(volume, converted_path,buf,size,
			offset,fp);
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

	if (volume->server->using_version->av_number < 30)
		rc=afp_read(volume, fp->forkid,offset,size,&buffer);
	else
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
		*eof=1;
		break;
	case kFPNoErr:
		break;
	}

	bytesleft-=buffer.size;
	totalsize+=buffer.size;
	return totalsize;
error:
	return -ret;

}


int ml_chmod(struct afp_volume * vol, const char * path, mode_t mode) 
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
#define TOCHECK_BITS \
	(S_IRUSR |S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | \
	 S_IROTH | S_IWOTH | S_IXOTH | S_IFREG )

	int ret=0,rc,rc2;
	struct afp_file_info fp,fp2;
	unsigned int dirid;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];

	if (volume_is_readonly(vol))
		return -EPERM;
	if (invalid_filename(vol->server,path)) 
		return -ENAMETOOLONG;

	/* There's no way to do this in AFP < 3.0 */
	if ((vol->server->using_version->av_number < 30) ||
		(~ vol->attributes & kSupportsUnixPrivs)) {
		return -ENOSYS;
	};

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(vol,converted_path,basename,&dirid );

	if ((rc=get_unixprivs(vol,
		dirid,basename, &fp))) 
		return rc;

	mode&=(~S_IFDIR);

	/* Don't bother updating it if it's already the same */
	if ((fp.unixprivs.permissions&(~S_IFDIR))==mode)
		return 0;

	/* If this is netatalk and chmod is broken, check the mode */
	/* This is where we'd do 2.x checking also */
	if ((vol->server->server_type==AFPFS_SERVER_TYPE_NETATALK) && 
	 (vol->extra_flags & VOLUME_EXTRA_FLAGS_VOL_CHMOD_KNOWN) &&
	 (vol->extra_flags & VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN)) {
		return -ENOSYS;
	}

	/* Check to make sure that we can; some servers (at least netatalk)
	   don't report an error when you try to setfileparm when you don't
	   own the file.  */
	/* Todo: do proper uid translation */

	if (translate_uidgid_to_client(vol,
		&fp.unixprivs.uid,&fp.unixprivs.gid))
		return -EIO;

	if ((fp.unixprivs.gid!=getgid()) && (fp.unixprivs.uid!=getuid())) {
		return -EPERM;
	}
	
	fp.unixprivs.permissions=mode;

	rc=set_unixprivs(vol, dirid,basename, &fp);

	if (rc==-ENOSYS) {
		return -ENOSYS;
	}


	/* If it is netatalk, check to see if that worked.  If not, 
	   never try this bitset again. */
	if ((mode & ~(AFP_CHMOD_ALLOWED_BITS_22)) && 
	 	(!(vol->extra_flags & VOLUME_EXTRA_FLAGS_VOL_CHMOD_KNOWN)) &&
		(vol->server->server_type==AFPFS_SERVER_TYPE_NETATALK))  
	{
		if ((rc2=get_unixprivs(vol,
			dirid, basename, &fp2))) 
			return rc2;
		vol->extra_flags|=VOLUME_EXTRA_FLAGS_VOL_CHMOD_KNOWN;
	
		if ((fp2.unixprivs.permissions&TOCHECK_BITS)==
			(fp.unixprivs.permissions&TOCHECK_BITS)) {
			vol->extra_flags&=~VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN;
		} else {
			vol->extra_flags|=VOLUME_EXTRA_FLAGS_VOL_CHMOD_BROKEN;
			return -EFAULT;
		}
	}

	return -ret;
}


int ml_unlink(struct afp_volume * vol, const char *path)
{
	int ret,rc;
	unsigned int dirid;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	
	if (volume_is_readonly(vol))
		return -EPERM;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (is_apple(converted_path))
		return 0;

	if (apple_translate(vol,converted_path))
		return 0;

	get_dirid(vol, (char * ) converted_path, basename, &dirid);

	if (is_dir(vol,dirid,basename) ) return -EISDIR;

	if (invalid_filename(vol->server,converted_path)) 
		return -ENAMETOOLONG;

	rc=afp_delete(vol,dirid,basename);

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




int ml_mkdir(struct afp_volume * vol, const char * path, mode_t mode) 
{
	int ret,rc;
	unsigned int result_did;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	unsigned int dirid;

	if (volume_is_readonly(vol))
		return -EPERM;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (invalid_filename(vol->server,path)) 
		return -ENAMETOOLONG;

	get_dirid(vol,converted_path,basename,&dirid);

	rc = afp_createdir(vol,dirid, basename,&result_did);

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

int ml_close(struct afp_volume * volume, const char * path, 
	struct afp_file_info * fp)
{

	int ret=0;
	char converted_path[AFP_MAX_PATH];

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path, (char *) path,AFP_MAX_PATH)) {
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
			return -1;
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
	return ret;
}

int ml_getattr(struct afp_volume * volume, const char *path, struct stat *stbuf)
{
	struct afp_file_info fp;
	unsigned int dirid;
	int rc;
	char resource;
	unsigned int filebitmap, dirbitmap;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];

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

	if (get_dirid(volume, converted_path, basename, &dirid)<0)
		return -ENOENT;

	dirbitmap=kFPAttributeBit 
		| kFPCreateDateBit | kFPModDateBit|
		kFPNodeIDBit |
		kFPParentDirIDBit | kFPOffspringCountBit;
	filebitmap=kFPAttributeBit | 
		kFPCreateDateBit | kFPModDateBit |
		kFPNodeIDBit |
		kFPFinderInfoBit |
		kFPParentDirIDBit;

	if (volume->server->using_version->av_number < 30) {
		if (path[0]=='/' && path[1]=='\0') {
			/* This will sound odd, but when referring to /, AFP 2.x
			   clients check on a 'file' with the volume name. */
			snprintf(basename,AFP_MAX_PATH,"%s",volume->name);
			dirid=1;
		}
		filebitmap |=( (resource==AFP_RESOURCE_TYPE_RESOURCE) ? 
				kFPRsrcForkLenBit : kFPDataForkLenBit );
	} else {
		filebitmap |= ((resource==AFP_RESOURCE_TYPE_RESOURCE) ? 
			kFPExtRsrcForkLenBit : kFPExtDataForkLenBit );
	}

	if (volume->attributes &kSupportsUnixPrivs) {
		dirbitmap|= kFPUnixPrivsBit;
		filebitmap|= kFPUnixPrivsBit;
	} else {
		dirbitmap|=kFPOwnerIDBit | kFPGroupIDBit;
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
	if (volume->server->using_version->av_number>=30) {
		stbuf->st_mode |= fp.unixprivs.permissions;
	} else {
		if (fp.isdir) 
			stbuf->st_mode = 0700 | S_IFDIR;
		else 
			stbuf->st_mode = 0600 | S_IFREG;
	}

	stbuf->st_uid=fp.unixprivs.uid;
	stbuf->st_gid=fp.unixprivs.gid;

	if (translate_uidgid_to_client(volume,
		&stbuf->st_uid,&stbuf->st_gid)) 
		return -EIO;
	if (stbuf->st_mode & S_IFDIR) {
		stbuf->st_nlink = fp.offspring +2;  
		stbuf->st_size = (fp.offspring *34) + 24;  
			/* This slight voodoo was taken from Mac OS X 10.2 */
	} else {
		stbuf->st_nlink = 1;
		stbuf->st_size = (resource ? fp.resourcesize : fp.size);
	}

#ifdef __linux__
	stbuf->st_ctim.tv_sec=fp.creation_date;
	stbuf->st_mtim.tv_sec=fp.modification_date;
#else
	stbuf->st_ctime=fp.creation_date;
	stbuf->st_mtime=fp.modification_date;
#endif

	switch (resource) {
	case AFP_RESOURCE_TYPE_PARENT2:
		stbuf->st_mode |= S_IFDIR;
		stbuf->st_mode &=~S_IFREG;
 		stbuf->st_mode |=S_IXUSR | S_IXGRP | S_IXOTH;
		break;
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

int ml_write(struct afp_volume * volume, const char * path, 
		const char *data, size_t size, off_t offset,
                  struct afp_file_info * fp, uid_t uid,
		gid_t gid)
{

	int ret,err=0;
	int totalwritten = 0;
	uint64_t sizetowrite, ignored;
	unsigned char flags = 0;
	unsigned int max_packet_size=volume->server->tx_quantum;
	off_t o=0;
	char converted_path[AFP_MAX_PATH];

/* TODO:
   - handle nonblocking IO correctly
*/
	if ((volume->server->using_version->av_number >= 30) && 
		(size>>2^32)) return -EFBIG;

	if (volume_is_readonly(volume))
		return -EPERM;

	if (convert_path_to_afp(volume->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	apple_translate(volume,converted_path);	


	if (is_volinfo(converted_path))
		return volinfo_write(volume, converted_path,data,size,
			offset,fp);

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
		set_uidgid(volume,fp,uid, gid);
		fp->unixprivs.permissions=0100644;
	};

	
	update_time(&fp->modification_date);
	flags|=kFPModDateBit;

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

		if (volume->server->using_version->av_number < 30) 
			ret=afp_write(volume, fp->forkid,
				offset+o,sizetowrite,
				(char *) data+o,&ignored);
		else 
			ret=afp_writeext(volume, fp->forkid,
				offset+o,sizetowrite,
				(char *) data+o,&ignored);
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


int ml_readlink(struct afp_volume * vol, const char * path, 
	char *buf, size_t size)
{
	int rc,ret;
	struct afp_file_info fp;
	struct afp_rx_buffer buffer;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	unsigned int dirid;
	char link_path[AFP_MAX_PATH];

	memset(buf,0,size);
	memset(link_path,0,AFP_MAX_PATH);

	buffer.data=link_path;
	buffer.maxsize=size;
	buffer.size=0;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(vol, converted_path, basename, &dirid);

	/* Open the fork */
	rc=afp_openfork(vol,0, dirid, 
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
	case 0:
		ret=0;
		break;
	case -1:
	default:
		ret=EFAULT;
		goto error;
	}

	/* Read the name of the file from it */
	if (vol->server->using_version->av_number < 30)
		rc=afp_read(vol, fp.forkid,0,size,&buffer);
	else 
		rc=afp_readext(vol, fp.forkid,0,size,&buffer);

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

	switch(afp_closefork(vol,fp.forkid)) {
	case kFPNoErr:
		break;
	default:
	case kFPParamErr:
	case kFPMiscErr:
		ret=EIO;
		goto error;
	}

	/* Convert the name back precomposed UTF8 */
	convert_path_to_unix(vol->server->path_encoding,
		buf,(char *) link_path,AFP_MAX_PATH);

	return 0;
	
error:
	return -ret;
}

int ml_rmdir(struct afp_volume * vol, const char *path)
{
	int ret,rc;
	unsigned int dirid;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];

	if (volume_is_readonly(vol))
		return -EPERM;

	if (invalid_filename(vol->server,path)) 
		return -ENAMETOOLONG;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	if (apple_translate(vol,converted_path))
		return 0;

	if (is_apple(converted_path)) 
		return 0;

	get_dirid(vol, converted_path, basename, &dirid);

	if (!is_dir(vol,dirid,basename)) return -ENOTDIR;

	rc=afp_delete(vol,dirid,basename);

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
		remove_did_entry(vol,converted_path);
		ret=0;
	}
	return -ret;
}

int ml_chown(struct afp_volume * vol, const char * path, 
	uid_t uid, gid_t gid) 
{

	struct afp_file_info fp;
	int rc;
	unsigned int dirid;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];

	if (volume_is_readonly(vol))
		return -EPERM;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (invalid_filename(vol->server,converted_path)) 
		return -ENAMETOOLONG;

	/* There's no way to do this in AFP < 3.0 */
	if ((vol->server->using_version->av_number < 30) ||
		(~ vol->attributes & kSupportsUnixPrivs)) {
		return -ENOSYS;
	};

	get_dirid(vol,converted_path,basename,&dirid );

	if ((rc=get_unixprivs(vol,
		dirid,basename, &fp)))
		return rc;

#if 0
FIXME
	set_uidgid(volume,&fp,uid,gid);
THIS IS the wrong set of returns to check...
#endif
	rc=set_unixprivs(vol, dirid, basename, &fp);

	switch(rc) {
	case -ENOSYS:
		return -ENOSYS;
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

int ml_truncate(struct afp_volume * vol, const char * path, off_t offset)
{
	int ret=0;
	char converted_path[AFP_MAX_PATH];
	struct afp_file_info *fp;
	int flags;

	if (volume_is_readonly(vol))
		return -EPERM;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	/* The approach here is to get the forkid by calling ml_open()
	   (and not afp_openfork).  Note the fake afp_file_info used
	   just to grab this forkid. */

	flags=O_WRONLY;
	if (invalid_filename(vol->server,converted_path)) 
		return -ENAMETOOLONG;

	if (is_volinfo(converted_path)) return 0;

	switch (apple_translate(vol,converted_path)) {
		case AFP_RESOURCE_TYPE_FINDERINFO:
		case AFP_RESOURCE_TYPE_COMMENT:
			/* Remove comment */
			return 0;
		default:
			break;
	}

	/* Here, we're going to use the untranslated path since it is
	   translated through the ml_open() */

	if ((ml_open(vol,path,flags,&fp))) {
		return ret;
	};

	if ((ret=zero_file(vol,fp->forkid,0)))
		goto out;

	afp_closefork(vol,fp->forkid);
	free(fp);

out:
	return -ret;
}


int ml_utime(struct afp_volume * vol, const char * path, 
	struct utimbuf * timebuf)
{

	int ret=0;
	unsigned int dirid;
	struct afp_file_info fp;
	char basename[AFP_MAX_PATH];
	char converted_path[AFP_MAX_PATH];
	int rc;

	if (volume_is_readonly(vol))
		return -EPERM;
	memset(&fp,0,sizeof(struct afp_file_info));

	fp.modification_date=timebuf->modtime;

	if (invalid_filename(vol->server,path)) 
		return -ENAMETOOLONG;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path,(char *) path,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(vol,converted_path,basename,&dirid );

	if (is_dir(vol,dirid,basename)) {
		rc=afp_setdirparms(vol,
			dirid,basename, kFPModDateBit, &fp);
	} else {
		rc=afp_setfileparms(vol,
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


int ml_symlink(struct afp_volume *vol, const char * path1, const char * path2) 
{

	int ret;
	struct afp_file_info fp;
	uint64_t written;
	int rc;
	unsigned int dirid2;
	char basename2[AFP_MAX_PATH];
	char converted_path1[AFP_MAX_PATH];
	char converted_path2[AFP_MAX_PATH];

	if (vol->server->using_version->av_number<30) {
		/* No symlinks for AFP 2.x. */
		ret=ENOSYS;
		goto error;
	}
	/* Yes, you can create symlinks for AFP >=30.  Tested with 10.3.2 */

	if (volume_is_readonly(vol))
		return -EPERM;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path1,(char *) path1,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path2,(char *) path2,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(vol,converted_path2,basename2,&dirid2 );

	/* 1. create the file */
	rc=afp_createfile(vol,kFPHardCreate,dirid2,basename2);
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
	rc=afp_openfork(vol,0,
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
	case 0:
		ret=0;
		break;
	case kFPVolLocked:
	case kFPDenyConflict:
	case kFPMiscErr:
	case kFPBitmapErr:
	case -1:
	default:
		ret=EFAULT;
		goto error;
	}


	/* Write the name of the file to it */

	rc=afp_writeext(vol,fp.forkid,0,strlen(converted_path1),
		converted_path1,&written);

	switch(afp_closefork(vol,fp.forkid)) {
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

	rc=afp_setfiledirparms(vol,dirid2,basename2,
		kFPFinderInfoBit, &fp);
	switch (rc) {
	case kFPAccessDenied:
		ret=EPERM;
		goto error;
	case kFPBitmapErr:
		/* This is the case where it isn't supported */
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

int ml_rename(struct afp_volume * vol,
	const char * path_from, const char * path_to) 
{
	int ret,rc;
	char basename_from[AFP_MAX_PATH];
	char basename_to[AFP_MAX_PATH];
	char converted_path_from[AFP_MAX_PATH];
	char converted_path_to[AFP_MAX_PATH];
	unsigned int dirid_from,dirid_to;

	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path_from,(char *) path_from,AFP_MAX_PATH)) {
		return -EINVAL;
	}
	if (convert_path_to_afp(vol->server->path_encoding,
		converted_path_to,(char *) path_to,AFP_MAX_PATH)) {
		return -EINVAL;
	}

	get_dirid(vol, converted_path_from, basename_from, &dirid_from);
	get_dirid(vol, converted_path_to, basename_to, &dirid_to);

	if (is_dir(vol,dirid_to,converted_path_to)) {
		rc=afp_moveandrename(vol,
			dirid_from,dirid_to,
			basename_from,basename_to,basename_from);
	} else {
		rc=afp_moveandrename(vol,
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
		switch(afp_delete(vol,dirid_to,basename_to)) {

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
		switch(afp_moveandrename(vol,
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

int ml_statfs(struct afp_volume * vol, const char *path, struct statvfs *stat)
{
	unsigned short flags;
	int ret;

	memset(stat,0,sizeof(*stat));

	if (vol->server->using_version->av_number<30)
		flags = kFPVolBytesFreeBit | kFPVolBytesTotalBit ;
	else 
		flags = kFPVolExtBytesFreeBit | kFPVolExtBytesTotalBit | kFPVolBlockSizeBit;

	ret=afp_getvolparms(vol,flags);
	switch(ret) {
	case kFPNoErr:
		break;
	case kFPParamErr:
	case kFPMiscErr:
	default:
		return -EIO;
	}
	if (vol->stat.f_bsize==0) vol->stat.f_bsize=4096;
	stat->f_blocks=vol->stat.f_blocks / vol->stat.f_bsize;
	stat->f_bfree=vol->stat.f_bfree / vol->stat.f_bsize;
	stat->f_bsize=vol->stat.f_bsize;
	stat->f_frsize=vol->stat.f_bsize;
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


