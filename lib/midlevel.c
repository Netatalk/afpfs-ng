

/*
    midlevel.c: some funtions to abstract some of the common functions 

    Copyright (C) 2006 Alex deVries <alexthepuffin@gmail.com>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/


#include "afp.h"

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

#ifdef FIXME
	if (is_volinfo(converted_path))
		return volinfo_readdir(converted_path,buf,filler,offset,fi);
#endif

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
				printf(
				"Could not get the filebase I just looked for.  Weird.\n");
				ret=ENOENT;
				goto error;
			}
	
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
			ret=EIO;
			goto error;
		}
	}

done:

    return 0;
error:
	return -ret;
}

