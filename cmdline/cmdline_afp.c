/* 
	portions Copyright (C) 2007 Alex deVries
	
*/

#include "afp.h"
#include "midlevel.h"
#include "map_def.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <ctype.h>

#include "cmdline_main.h"

static char curdir[AFP_MAX_PATH];
static struct afp_url url;

#define DEFAULT_DIRECTORY "/"

static struct afp_server * server = NULL;
struct afp_volume * vol= NULL;

static int recursive_get(char * path);

static unsigned int tvdiff(struct timeval * starttv, struct timeval * endtv)
{
	unsigned int d;
	d=(endtv->tv_sec - starttv->tv_sec) * 1000;
	d+= (endtv->tv_usec - starttv->tv_usec) / 1000;
	return d;
	
}

static void printdiff(struct timeval * starttv, struct timeval *endtv, 
	unsigned long long * amount_written)
{
	unsigned int diff;
	unsigned long long kb_written;

	diff=tvdiff(starttv,endtv);
	float frac = ((float) diff) / 1000.0; /* Now in seconds */
	printf("Transferred %lld bytes in ",*amount_written);
	printf("%.3f seconds. ",frac);

	/* Now calculate the transfer rate */
	kb_written = (*amount_written/1000);
	float rate = (kb_written)/frac;
	printf("(%.0f kB/s)\n", rate);
}

static int get_server_path(char * filename,char * server_fullname)
{
	if (filename[0]!='/') {
		if (strlen(curdir)==1) 
			snprintf(server_fullname,PATH_MAX,"/%s",filename);
		else
			snprintf(server_fullname,PATH_MAX,"%s/%s",curdir,filename);
	} else {
		snprintf(server_fullname,PATH_MAX,"%s",filename);
	}
	return 0;
}

static void convert_time(struct tm * tm,const time_t t)
{
	memset(tm,0,sizeof(tm));
	tm->tm_sec=t;
}

static void print_file_details(struct afp_file_info * p)
{
	struct tm * mtime;
	time_t t,t2;
#define DATE_LEN 32
	char datestr[DATE_LEN];
	char mode_str[11];
	uint32_t mode;
	struct stat stat;

	afp_unixpriv_to_stat(p,&stat);
	mode=stat.st_mode;

	sprintf(mode_str,"----------");

	t2=time(NULL);
	t=p->modification_date;
	mtime=localtime(&t);

	if (p->isdir) mode_str[0]='d';

	if (mode & S_IRUSR) mode_str[1]='r';
	if (mode & S_IWUSR) mode_str[2]='w';
	if (mode & S_IXUSR) mode_str[3]='x';
	
	if (mode & S_IRGRP) mode_str[4]='r';
	if (mode & S_IWGRP) mode_str[5]='w';
	if (mode & S_IXGRP) mode_str[6]='x';
	
	if (mode & S_IROTH) mode_str[7]='r';
	if (mode & S_IWOTH) mode_str[8]='w';
	if (mode & S_IXOTH) mode_str[9]='x';
	

	strftime(datestr,DATE_LEN,"%F %H:%M", mtime);

	printf("%s %6lld %s %s\n",mode_str,p->size,datestr,p->name);

}

static int server_subconnect(void) 
{
	struct afp_connection_request * conn_req;

#define BUFFER_SIZE 2048
	conn_req = malloc(sizeof(struct afp_connection_request));

        memset(conn_req, 0,sizeof(struct afp_connection_request));

        conn_req->url=url;
	conn_req->url.requested_version=31;
	if (strlen(url.uamname)>0) {
		if ((conn_req->uam_mask = find_uam_by_name(url.uamname))==0) {
			printf("I don't know about UAM %s\n",url.uamname);
			return -1;
		}
		
	} else {
        	conn_req->uam_mask=default_uams_mask();
	}
	if ((server=afp_server_full_connect(NULL, conn_req))==NULL) {
		goto error;
	}

	printf("Connected to server %s using UAM \"%s\"\n",
		server->server_name_precomposed, uam_bitmap_to_string(server->using_uam));

	free(conn_req);

	return 0;
error:
	free(conn_req);
	printf("Could not connect\n");
	return -1;
}

int com_pass(char * arg)
{
	if (strlen(arg)==0) {
		printf("You must specify a password\n");
		return -1;
	} else {
		printf("Password set.\n");
	}

	strncpy(url.password,arg,AFP_MAX_PASSWORD_LEN);
	return 0;

}


int com_user(char * arg)
{
	if (strlen(arg)==0) {
		printf("You must specify a user\n");
	return -1;
	}

	strncpy(url.username,arg,AFP_MAX_PASSWORD_LEN);
	printf("username is now %s\n",url.username);
	return 0;
}


int com_connect(char * arg)
{
	struct afp_url tmpurl;
	if (!arg)
		arg = "";

	if (server) {
		printf("You're already connected to a server\n");
		goto error;
	}

	afp_default_url(&tmpurl);

	/* First, try to parse the URL */
	
	if (afp_parse_url(&tmpurl,arg,0)!=0) {
		/* Okay, this isn't a real URL */
		printf("Could not parse url, let me see if this is a server name...\n");
		if (gethostbyname(arg)) 
			memcpy(&url.servername,arg,AFP_SERVER_NAME_LEN);
		else {
			printf("Cannot understand server name or url %s\n",arg);
			return -1;
		}
	} else {
		url=tmpurl;

	}


	if (server_subconnect()) {
		printf("Could not connect\n");
		goto error;
	};

	return 0;
error:
	return -1;

}


int com_dir(char * arg)
{
	if (!arg)
		arg = "";

	struct afp_file_info *filebase = NULL, *p;

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	if (strlen(url.volumename)==0) {
		int i;
		printf("You're not connected to a server, so I will show you which volumes you can choose from.\n");
		for (i=0;i<server->num_volumes;i++) {
			printf("Volume %s\n",
			server->volumes[i].volume_name_printable);
		}
		goto out;

	}
	
	if (ml_readdir(vol,curdir,&filebase)) goto error;

	if (filebase==NULL) goto out;
	for (p=filebase;p;p=p->next) {
		print_file_details(p);
	}

out:
	
	return 0;
error:
	return -1;
}


int com_touch(char * filename)
{
	char * basename = filename;
	char server_fullname[AFP_MAX_PATH];
	int ret;

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	get_server_path(basename,server_fullname);

	ret=ml_creat(vol,server_fullname,0600);
	return 0;
error:
	return -1;

	return 0;
}

int com_chmod(char * arg)
{
	unsigned int mode;
	char basename[PATH_MAX];
	char server_fullname[AFP_MAX_PATH];
	int ret;

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	if (sscanf(arg,"%o %s",&mode,(char *) &basename)!=2) {
		printf("expecting format: chmod <privs> <filename>\n");
		goto error;
	}
	get_server_path(basename,server_fullname);

printf("Changing mode of %s to %o\n",server_fullname,mode);
	ret=ml_chmod(vol,server_fullname,mode);
	return 0;
error:
	return -1;
}


int com_put(char *filename)
{
	int ret, amount_read;
	struct afp_file_info *fp;
	int offset=0;
#define PUT_BUFSIZE 1024
	char buf[PUT_BUFSIZE];
	int fd;
	char server_fullname[AFP_MAX_PATH];
	char * basename;
	uid_t uid;
	gid_t gid;
	struct stat localstat;
	unsigned long long amount_written=0;
	struct timeval starttv,endtv;

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	/* FIXME find basename */
	basename=filename;

	get_server_path(basename,server_fullname);

	/* FIXME need a better way to get server's uid/gid */

	uid=getuid();
	gid=getgid();

	if (stat(filename, &localstat)!=0) {
		perror("Opening local file");
	}

	fd = open(filename,O_RDONLY);

	if (fd<0) {
		printf("Problem opening local file\n");
		perror("opening");
		goto error;
	}

	gettimeofday(&starttv,NULL);

	ret = ml_open(vol,server_fullname,O_CREAT | O_RDWR,&fp);

	if (ret<0) {
		printf("Problem opening file %s on server\n",basename);
		goto out;
	}

	/* Now set various permissions */

	ret=ml_chmod(vol,server_fullname,localstat.st_mode);
	if (ret==-ENOSYS) printf("cannot change permissions\n");
	if (ret) {
		printf("Could not change permissions to 0%o\n",
			localstat.st_mode);
	}

	while (1) {
		amount_read=read(fd,buf,PUT_BUFSIZE);
		if (amount_read<0) {
			perror("Reading");
			goto out;
		}
		if (amount_read==0) goto out;
		ret=ml_write(vol,server_fullname,buf,amount_read,
			offset,fp,uid,gid);
		offset+=amount_read;
		amount_written+=amount_read;
		if (ret<0) {
			printf("IO error when writing to server, error %d\n", 
				ret);
			goto out;
		}
	}

/* FIXME time */

out:
	gettimeofday(&endtv,NULL);
	printdiff(&starttv, &endtv,&amount_written);

	close(fd);
	ml_close(vol,server_fullname,fp);
	return 0;

error:
	return -1;

}

static int retrieve_file(char * arg,int fd, int silent, 
	struct stat *stat, unsigned long long * amount_written)
{
	int flags=O_RDONLY;
	int ret=0;
	struct afp_file_info * fp;
	char path[PATH_MAX];
	off_t offset = 0;
#define BUF_SIZE 1024
	size_t size = BUF_SIZE;
	char buf[BUF_SIZE];
	int eof;
	unsigned long long total=0;
	struct timeval starttv,endtv;

	*amount_written=0;

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	get_server_path(arg,path);

	gettimeofday(&starttv,NULL);

	if ((ret=ml_getattr(vol,path,stat))) {
		printf("Could access file %s, return codee %d\n",path,ret);
		goto error;
	}

	ret = ml_open(vol,path,flags,&fp);
	
	if (ret) {
		printf("Could not open %s, %d\n",arg,ret);
		goto error;
	}

	ret =1; /* to get the loop going */
	while (ret) 
	{
		memset(buf,0,BUF_SIZE);
		ret = ml_read(vol,path,buf,size,offset,fp,&eof);
		if (ret<=0) goto out;
		total+=write(fd,buf,ret);
		offset+=ret;
		if ((eof==1) || (ret==0)) goto out;
	}
out:

	if (fd>1) close(fd);
	ml_close(vol,path,fp);

	free(fp);

	if (silent==0) {
		gettimeofday(&endtv,NULL);
		printdiff(&starttv, &endtv,&total);
	}

	*amount_written=total;
	return 0;
error:
	return -1;
}

static int com_get_file(char * filename, int silent, 
	unsigned long long * total) 
{
	int fd;
	struct stat stat;
	char * localfilename;

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}
	localfilename=basename(filename);

	printf("    Getting file %s\n",filename);

	if ((access(localfilename,W_OK)) && (errno!=ENOENT)) {
		printf("Trying to access %s\n",localfilename);
		perror("Access local file for write");
		goto error;
	}

	fd=open(localfilename,O_CREAT | O_TRUNC| O_RDWR);
	if (fd<0) {
		perror("Opening file");
		goto error;
	}
	retrieve_file(filename,fd,silent,&stat, total);

	close(fd);
	chmod(localfilename,stat.st_mode);
	chown(localfilename,stat.st_uid,stat.st_gid);
	return 0;
error:
	return -1;
}

int com_get (char *arg)
{
	unsigned long long amount_written;
	char newpath[255];

	if ((arg[0]=='-') && (arg[1]=='r') && (arg[2]==' ')) {
		arg+=3;
		while ((arg) && (isspace(arg[0]))) arg++;
		snprintf(newpath,255,"%s/%s",curdir,arg);
		return recursive_get(newpath);
	} else 
		return com_get_file(arg,0, &amount_written);
}


int com_view (char * arg)
{
	unsigned long long amount_written;
	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}
	printf("Viewing: %s\n",arg);
	retrieve_file(arg,fileno(stdout),1,NULL, &amount_written);
	return 0;
error:
	return -1;
}

int com_rename (char * arg)
{

	char from_path[AFP_MAX_PATH], to_path[AFP_MAX_PATH];
	char full_from_path[AFP_MAX_PATH], full_to_path[AFP_MAX_PATH];
	struct stat stbuf;
	int ret;

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	if (sscanf(arg,"%s %s",(char *) &from_path,(char *) &to_path)!=2) {
		printf("expecting format: mv <from> <to>\n");
		goto error;
	}
	get_server_path(from_path,full_from_path);
	get_server_path(to_path,full_to_path);
printf("Moving from %s to %s\n",full_from_path,full_to_path);

	/* Make sure from_file exists */
	if ((ret=ml_getattr(vol,full_from_path,&stbuf))) {
		printf("Could not find file %s, error was %d\n",
			full_from_path,ret);
		goto error;
	}

	/* Make sure to_file doesn't exist */
	ret=ml_getattr(vol,full_to_path,&stbuf);
	if ((ret==0) && ((stbuf.st_mode & S_IFDIR)==0)) {
		printf("File %s already exists, error: %d\n", 
			full_to_path,ret);
		goto error;
	}

	if ((ret=ml_rename(vol,full_from_path, full_to_path))) goto error;

	return 0;
error:
	return -1;
}

int com_delete (char *arg)
{
	
	int ret;
	char server_fullname[AFP_MAX_PATH];

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}
	get_server_path(arg,server_fullname);

	if ((ret=ml_unlink(vol,server_fullname))) {
		printf("Could not remove %s, error code is %d\n",
			arg,ret);
		goto error;
	}
	printf("Removed file %s\n",arg);
	return (1);
error:
	return -1;
}

int com_mkdir(char *arg)
{
	
	int ret;
	char server_fullname[AFP_MAX_PATH];
	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	get_server_path(arg,server_fullname);

	if ((ret=ml_mkdir(vol,server_fullname,0755))) {
		printf("Could not create directory %s, error code is %d\n",
			arg,ret);
		goto error;
	}
	printf("Created directory %s\n",arg);
	return 0;
error:
	return -1;
}

int com_rmdir(char *arg)
{
	
	int ret;
	char server_fullname[AFP_MAX_PATH];

	if (server==NULL) {
		printf("You're not connected yet to a server\n");
		goto error;
	}

	get_server_path(arg,server_fullname);

	if ((ret=ml_rmdir(vol,server_fullname))) {
		printf("Could not remove directory %s, error code is %d\n",
			arg,ret);
		goto error;
	}
	printf("Removed directory %s\n",arg);
	return 0;
error:
	return -1;
}

int com_status(char * arg)
{
	int len=40960;
	char text[40960];

	afp_status_header(text,&len);
	printf(text);

	len=40960;
	afp_status_server(server,text,&len);
	printf(text);
	return 0;
}

int com_passwd(char * arg)
{
	char * p;
	int ret;
	char newpass[AFP_MAX_PASSWORD_LEN];

	if (!server) {
		printf("Not connected to a server\n");
		goto error;
	}
	p = getpass("New password: ");
	strncpy(newpass,p,AFP_MAX_PASSWORD_LEN);
	ret=ml_passwd(server,url.username,url.password,newpass);
	if (ret) {
		printf("Could not change password\n");
		goto error;
	}

	return 0;
error:
	return -1;
}

static void print_size(unsigned long l)
{

	if (l>(1073741824)) {
		printf("%4ldTb",l/1073741824);
		return;
	} 
	if (l>(1048576)) {
		printf("%4ldGb",l/1048576);
		return;
	} 
	if (l>(1024)) {
		printf("%4ldMb",l>>10);
		return;
	} 
	printf("%4ldKb\n",l);

}

int com_statvfs(char * arg)
{
	struct statvfs stat;
	unsigned long avail, used,total;
	unsigned int portion;
	int i;
	ml_statfs(vol,"/",&stat);

	avail=stat.f_bavail*4;
	used=(stat.f_blocks-stat.f_bavail)*4;
	total=avail+used;

	portion = (unsigned int) (((float) used*100)/((float) avail+(float) used));

	printf("Volume ");
	for (i=strlen(vol->volume_name_printable)-6;i>0;i--) printf(" ");

	if (strstr(arg,"-h")) {
		printf("  Size   Used  Avail  Capacity\n");
		printf("%s ", vol->volume_name_printable);
		print_size(total); printf(" ");
		print_size(used); printf(" ");
		print_size(avail); printf(" ");
		printf("   %d%%\n",portion);
	} else {
		avail*=2;
		used*=2;
		total*=2;
		printf(" 512-blocks     Used     Available  Use%%\n");
		printf("%s %10ld %10ld %10ld  %d%%\n", vol->volume_name_printable,
			total, used, avail,portion);
	}
	return 0;
}


int com_lcd(char * path)
{

	int ret;
	char curpath[PATH_MAX];

	ret=chdir(path);
	if (ret!=0) 
		perror("Changing directories");
	else {
		getcwd(curpath,PATH_MAX);
		printf("Now in local directory %s\n",curpath);
	}
	return ret;

}

/* Change to the directory ARG. */
int com_cd (char *path)
{

	int ret;
	char newdir[AFP_MAX_PATH];
	char * p;
	struct stat stbuf;

	if (server==NULL) {
		printf("You're not connected to a server yet\n");
		goto error;
	}

printf("Changing to %s\n",path);

	if (strlen(url.volumename)==0) {
		/* Ah, we're not connected to a volume*/
		char volname[AFP_VOLUME_NAME_UTF8_LEN];
		unsigned int len=0;
		char mesg[1024];

		if (strlen(path)==0) return -1;

		/* Setup volname to contain just the volume name */
		memcpy(volname,path,AFP_VOLUME_NAME_UTF8_LEN);
		if((p=strchr(volname,'/'))) *p='\0';

		vol=malloc(sizeof(struct afp_volume));
		vol->server=server;
		vol->mapping= AFP_MAPPING_LOGINIDS;

		memcpy(vol->volume_name,volname,AFP_VOLUME_NAME_UTF8_LEN);
		if (afp_connect_volume(vol,server,mesg,&len,1024 ))
		{
			printf("Could not access volume %s\n",volname);
			goto error;
		}

		memcpy(url.volumename,volname,AFP_VOLUME_NAME_UTF8_LEN);
		printf("Connected to volume %s\n",volname);

		if (strlen(volname)>=strlen(path)) {
			return 1;
		}
	}

	/* Chop off the last / */
	if (((strlen(path)>1) && (path[strlen(path)-1]=='/'))) 
		path[strlen(path)-1]='\0';
	if (((strlen(curdir)>1) && (curdir[strlen(curdir)-1]=='/')))
		curdir[strlen(curdir)-1]='\0';

	if (strncmp(path,"..", AFP_MAX_PATH)==0) {
		/* go back one */

		if (strlen(curdir)==1) {
			printf("Already at top level\n");
			return 0;
		}
		if ((p=strrchr(curdir,'/'))) {
			if (p==curdir) snprintf(curdir,AFP_MAX_PATH,"/");
			else *p='\0';
		} else {
			printf("Internal error\n");	
			goto error;
		}
	} else {
printf("Starting path: %s, %s\n",path,curdir);
		if (path[0]=='/')
			memcpy(newdir,path, AFP_MAX_PATH);
		else 
			if ((strlen(path)==1) && (path[0]=='/'))
				snprintf(newdir,AFP_MAX_PATH,"/%s",path);
			else 
				snprintf(newdir,AFP_MAX_PATH,
					"%s/%s",curdir,path);

		ret=ml_getattr(vol,newdir,&stbuf);

		if ((ret==0) && (stbuf.st_mode & S_IFDIR)) {
			memcpy(curdir,newdir,AFP_MAX_PATH);
		} else {
			if ((stbuf.st_mode & S_IFDIR)==0) {
				printf("%s is not a directory\n",newdir);
			} else {
				printf("Error %d\n",ret);
				goto error;
			}
		}

	
	}
	
	/* To change directory, get a file list and grab the did. */
	return 0;
error:
	return -1;
}

/* Print out the current working directory. */
int com_pwd (char * ignore)
{
	if (server==NULL) {
		printf("You're not connected to a server yet\n");
		goto error;
	}

	printf("Now in directory %s.\n",curdir);
	return 0;
error:
	return -1;
}

static int get_dir(char * server_base, char * path, 
	unsigned long long * total)
{
	struct afp_file_info * p, *filebase;
	char total_path[AFP_MAX_PATH];	
	unsigned long long amount_written, local_total=0;

	if (strcmp(server_base,"/")==0) 
		snprintf(total_path,AFP_MAX_PATH,"/%s",path);
	else
		snprintf(total_path,AFP_MAX_PATH,"%s/%s",server_base,path);

	printf("Getting directory %s\n",total_path);

	mkdir(path,0755);
	chdir(path);

	if (ml_readdir(vol,total_path,&filebase)) goto error;
	if (filebase==NULL) goto out;
	for (p=filebase;p;p=p->next) {
		if (p->isdir) {
			get_dir(total_path,p->name, &amount_written);
		} else {
			snprintf(curdir,AFP_MAX_PATH,"%s",total_path);
			com_get_file(p->name,1, &amount_written);
		}
		local_total+=amount_written;
	}

out:

	*total=local_total;
	chdir("..");
	
	return 0;
error:
	chdir("..");
	return -1;

}


static int recursive_get(char * path)
{
	char * dirc = strdup(path);
	char * base = basename(path);
	char * dir = dirname(dirc);

	struct timeval starttv, endtv;
	unsigned long long amount_written;

	gettimeofday(&starttv,NULL);
	get_dir(dir,base, &amount_written);
	gettimeofday(&endtv,NULL);

	printdiff(&starttv,&endtv, &amount_written);

	return 0;

}

static struct libafpclient afpclient = {
	.unmount_volume = NULL,
	.log_for_client = stdout_log_for_client,
	.forced_ending_hook = cmdline_forced_ending_hook,
	.scan_extra_fds = NULL,
	.loop_started = cmdline_loop_started,
};

static void * cmdline_server_startup(int recursive)
{

	char mesg[1024];
	unsigned int len=0;
	struct stat stbuf;
	int ret;

	if (server_subconnect()) goto error;

	if (strlen(url.volumename)==0) {
		int i;
		printf("Specify a volume with 'cd volume'.  Choose one of:\n");
			for (i=0;i<server->num_volumes;i++) {
				printf("%s ",
				server->volumes[i].volume_name_printable);
			}
		printf("\n");
		trigger_connected();
		return NULL;
	}

	vol=malloc(sizeof(struct afp_volume));
	vol->server=server;
	vol->mapping= AFP_MAPPING_LOGINIDS;

	bcopy(url.volumename,vol->volume_name,AFP_VOLUME_NAME_UTF8_LEN);

	if (afp_connect_volume(vol,server,mesg,&len,1024 ))
	{
		printf("Could not access volume %s\n",url.volumename);
		goto error;
	}


	trigger_connected();

	if (strlen(url.path)==0) 
		return NULL;


	ret=ml_getattr(vol,url.path,&stbuf);

	if (ret) {
		printf("Could not open %s\n",url.path);
		just_end_it_now();
		goto error;
	}

	if (stbuf.st_mode & S_IFDIR) {
		snprintf(curdir,AFP_MAX_PATH,"%s",url.path);
		printf("In directory %s\n",url.path);
		if (recursive) {
			recursive_get(url.path);
		}
		
	} else {
		com_get(url.path);
		just_end_it_now();
	}

	return NULL;

error:
	printf("Error\n");
	return (void *) -1;


}

void cmdline_afp_exit(void)
{

	afp_unmount_volume(vol);

}

void * cmdline_afp_start_loop(void * other)
{
	afp_main_loop(-1);
	return NULL;
}

void cmdline_afp_setup_client(void) 
{
	client_setup(&afpclient);

}


int cmdline_afp_setup(int recursive, char * url_string)
{
	struct passwd * passwd;

	snprintf(curdir,PATH_MAX,"%s",DEFAULT_DIRECTORY);

	if (init_uams()<0) return -1;

	afp_default_url(&url);

	passwd = getpwuid(getuid());
	strncpy(url.username, passwd->pw_name,AFP_MAX_USERNAME_LEN);
	if ((url_string) && (strlen(url_string)>1)) {

		if (afp_parse_url(&url,url_string,0)) {
			printf("Could not parse url.\n");
		}
		if (strlen(url.uamname)>0) {
		}
		trigger_connected();
		cmdline_server_startup(recursive);
	}
	return 0;
}

