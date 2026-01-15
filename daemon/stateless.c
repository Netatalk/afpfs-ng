#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <sys/un.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <sys/shm.h>

#include "config.h"
#include <afp.h>
#include "afpfsd.h"
#include "uams_def.h"
#include "map_def.h"
#include "libafpclient.h"
#include "afpsl.h"

#define default_uam "Cleartxt Passwrd"

#define AFPFSD_FILENAME "afpfsd"

static unsigned int uid, gid=0;
static int changeuid=0;
static int changegid=0;

struct afpfsd_connect {
	int fd;
	unsigned int len;
	char data[MAX_CLIENT_RESPONSE+200];
	void (*print) (const char * text);
	char * shmem;
};

static struct afpfsd_connect connection;

static int start_afpfsd(void)
{
	char *argv[1];

	argv[0]=0;
	if (fork()==0) {
		char filename[PATH_MAX];
		if (changegid) {
			if (setegid(gid)) {
				perror("Changing gid");
				return -1;
			}
		}
		if (changeuid) {
			if (seteuid(uid)) {
				perror("Changing uid");
				return -1;
			}
		}
		snprintf(filename,PATH_MAX,"%s/%s",BINDIR,AFPFSD_FILENAME);
		if (access(filename,X_OK)) {
			printf("Could not find server (%s)\n",
				filename);
				return -1;
		}


		execvp(filename,argv);
		
		printf("done threading\n");
	}
	return 0;
}

int daemon_connect(unsigned int uid) 
{
	int sock;
	struct sockaddr_un servaddr;
	char filename[PATH_MAX];
	unsigned char trying=2;
	int ret;

	if ((sock=socket(AF_UNIX,SOCK_STREAM,0)) < 0) {
		perror("Could not create socket\n");
		return -1;
	}
	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	sprintf(filename,"%s-%d",SERVER_FILENAME,uid);

	strcpy(servaddr.sun_path,filename);

	while(trying) {
		ret=connect(sock,(struct sockaddr*) &servaddr,
			sizeof(servaddr.sun_family) + 
			sizeof(servaddr.sun_path));
		if (ret<0) perror("connect");

		if (ret>=0) goto done;

		printf("The afpfs daemon does not appear to be running for uid %d, let me start it for you\n", uid);

		if (start_afpfsd()!=0) {
			printf("Error in starting up afpfsd\n");
			goto error;
		}
		if ((connect(sock,(struct sockaddr*) &servaddr,
			sizeof(servaddr.sun_family) + 
			sizeof(servaddr.sun_path))) >=0) 
				goto done;
		trying--;
	}
error:
	perror("Trying to startup afpfsd");
	return -1;

done:
	connection.fd=sock;
	return 0;
}

/* read_answer()
 *
 * Reads the answer from afpfsd.
 * Returns:
 * -1: timeout or select error
 * >0: afpfsd header error
 */

static int read_answer(void)
{
	unsigned int expected_len=0, packetlen;
	struct timeval tv;
	fd_set rds,ords;
	int ret;
	struct afp_server_response_header * answer = (void *) connection.data;

	memset(connection.data,0,MAX_CLIENT_RESPONSE);
	connection.len=0;

	FD_ZERO(&rds);
	FD_SET(connection.fd,&rds);
	while (1) {
		tv.tv_sec=30; tv.tv_usec=0;
		ords=rds;
		ret=select(connection.fd+1,&ords,NULL,NULL,&tv);
		if (ret==0) {
			printf("No response from server, timed out.\n");
			return -1;
		}
		if (FD_ISSET(connection.fd,&ords)) {
			packetlen=read(connection.fd,
				connection.data+connection.len,
				MAX_CLIENT_RESPONSE-connection.len);
			if (packetlen<=0) {
				printf("Dropped connection\n");
				goto done;
			}
			if (connection.len==0) {  /* This is our first read */
				expected_len=
					((struct afp_server_response_header *) 
					connection.data)->len;
			}
			connection.len+=packetlen;
			if (connection.len==expected_len)
				goto done;
			if (ret<0) goto error;

		}
	}

done:

	return ((struct afp_server_response_header *) connection.data)->result;

error:
	return -1;
}

static int send_command(unsigned int len, char * data, unsigned int num)
{
	/* num is just used for debugging */
	int ret;

	ret = write(connection.fd,data,len);
	return  ret;
}

static void conn_print(const char * text) 
{
	printf(text);
}

void afp_sl_conn_setup(void)
{
	connection.print=conn_print;
}


int afp_sl_exit(void)
{
	struct afp_server_exit_request req;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	req.header.command=AFP_SERVER_COMMAND_EXIT;
	req.header.close=1;
	req.header.len=sizeof(req);
	send_command(sizeof(req),(char *) &req,AFP_SERVER_COMMAND_EXIT);

	return read_answer();
}

/* afp_sl_status()
 *
 * Returns:
 * AFP_SERVER_RESULT_AFPFSD_ERROR: could not connect to afpfsd
 */

int afp_sl_status(const char * volumename, const char * servername,
	char * text, unsigned int * remaining)
{
	struct afp_server_status_request req;
	struct afp_server_status_response * resp;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	req.header.command=AFP_SERVER_COMMAND_STATUS;
	req.header.close=1;
	req.header.len=sizeof(req);

	if (volumename) snprintf(req.volumename,AFP_VOLUME_NAME_UTF8_LEN,
		volumename);
	if (servername) snprintf(req.servername,AFP_SERVER_NAME_LEN,
		servername);

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_STATUS);

	*remaining-=connection.len;

	ret=read_answer();

	snprintf(text,connection.len,connection.data+
		sizeof(struct afp_server_status_response));

	return ret;
}

/* afp_sl_getvolid()
 *
 * Result header returns:
 * AFP_SERVER_RESULT_AFPFSD_ERROR
 * AFP_SERVER_RESULT_OKAY
 *
 */

int afp_sl_getvolid(struct afp_url * url, volumeid_t *volid)
{
	struct afp_server_getvolid_request req;
	struct afp_server_getvolid_response * reply;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	memset(&req,0,sizeof(req));

	req.header.close=1;
	req.header.len = sizeof(struct afp_server_getvolid_request);
	req.header.command=AFP_SERVER_COMMAND_GETVOLID;

	memcpy(&req.url,url,sizeof(*url));

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_GETVOLID);

	ret=read_answer();

	reply = (void *) connection.data;
	reply->header.result=ret;


	if (ret!=AFP_SERVER_RESULT_OKAY)
		return ret;


	memcpy(volid,&reply->volumeid,sizeof(volumeid_t));

done:
	return reply->header.result;
}

int afp_sl_stat(volumeid_t * volid, const char * path,
	struct afp_url * url, struct stat * stat)
{
	struct afp_server_stat_request request;
	struct afp_server_stat_response * response;
	volumeid_t tmpvolid;
	volumeid_t * volid_p = volid;
	char * tmppath = path;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	request.header.close=1;
	request.header.len=sizeof(struct afp_server_stat_request);
	request.header.command=AFP_SERVER_COMMAND_STAT;
	
	if (volid==NULL) {
		ret = afp_sl_getvolid(url,&tmpvolid);
		if (ret) return ret;

		tmppath=url->path;
		volid_p = &tmpvolid;
	}

	memcpy(&request.volumeid,volid_p, sizeof(volumeid_t));
	memcpy(request.path,tmppath,AFP_MAX_PATH);

	send_command(sizeof(request),(char *)&request,AFP_SERVER_COMMAND_STAT);

	ret=read_answer();

	response = (void *) connection.data;

	memcpy(stat,&response->stat,sizeof(struct stat));

	return response->header.result;


}

int afp_sl_open(volumeid_t * volid, const char * path,
        struct afp_url * url,unsigned int *fileid,
        unsigned int mode)
{
	struct afp_server_open_request request;
	struct afp_server_open_response * response;
	volumeid_t tmpvolid;
	volumeid_t * volid_p = volid;
	char * tmppath = path;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	request.header.close=1;
	request.header.len=sizeof(struct afp_server_open_request);
	request.header.command=AFP_SERVER_COMMAND_OPEN;
	
	if (volid==NULL) {
		ret = afp_sl_getvolid(url,&tmpvolid);
		if (ret) return ret;

		tmppath=url->path;
		volid_p = &tmpvolid;
	}

	memcpy(&request.volumeid,volid_p, sizeof(volumeid_t));
	memcpy(request.path,tmppath,AFP_MAX_PATH);
	request.mode=mode;

	send_command(sizeof(request),(char *)&request,AFP_SERVER_COMMAND_OPEN);

	ret=read_answer();

	response = (void *) connection.data;

	*fileid=response->fileid;

	return response->header.result;
}


int afp_sl_read(volumeid_t * volid, unsigned int fileid, unsigned int resource,
        unsigned long long start,
        unsigned int length, unsigned int * received,
        unsigned int * eof, char * data)
{
	struct afp_server_read_request request;
	struct afp_server_read_response * response;
	int ret;
	char * dataptr;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	request.header.close=1;
	request.header.len=sizeof(struct afp_server_read_request);
	request.header.command=AFP_SERVER_COMMAND_READ;
	memcpy(&request.volumeid,volid,sizeof(volumeid_t));
	request.fileid=fileid;
	request.start=start;
	request.length=length;
	request.resource=resource;

	send_command(sizeof(request),(char *)&request,AFP_SERVER_COMMAND_READ);

	ret=read_answer();

	response = (void *) connection.data;
	*received=response->received;
	*eof=response->eof;

	dataptr = ((char *) response ) + sizeof(struct afp_server_read_response);

	memcpy(data,dataptr,*received);

	return response->header.result;
}

int afp_sl_close(volumeid_t *volid, unsigned int fileid)
{
	struct afp_server_close_request request;
	struct afp_server_close_response * response;
	int ret;
	char * dataptr;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	request.header.close=1;
	request.header.len=sizeof(struct afp_server_close_request);
	request.header.command=AFP_SERVER_COMMAND_CLOSE;
	memcpy(&request.volumeid,volid,sizeof(volumeid_t));
	request.fileid=fileid;

	send_command(sizeof(request),(char *)&request,AFP_SERVER_COMMAND_CLOSE);

	ret=read_answer();

	response = (void *) connection.data;

	return response->header.result;
}

int afp_sl_readdir(volumeid_t * volid, const char * path, struct afp_url * url,
	int start, int count, unsigned int * numfiles, 
	struct afp_file_info_basic **data,
	int * eod)
{
	struct afp_server_readdir_request req;
	struct afp_server_readdir_response * mainrep;
	int ret;
	char * mainresp;
	char * tmppath = path;
	unsigned int size;
	volumeid_t * volid_p = volid;
	volumeid_t tmpvolid;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	if (eod) *eod=0;

	memset(&req,0,sizeof(req));

	req.header.close=1;
	req.header.len = sizeof(struct afp_server_readdir_request);
	req.header.command=AFP_SERVER_COMMAND_READDIR;
	req.start=start;
	req.count=count;

	if (volid==NULL) {
		ret=afp_sl_getvolid(url,&tmpvolid);
		if (ret) return ret;
		tmppath=url->path;
		volid_p = &tmpvolid;
	}

	memcpy(&req.volumeid,volid_p, sizeof(volumeid_t));
	memcpy(req.path,tmppath,AFP_MAX_PATH);

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_READDIR);

	ret=read_answer();

	mainrep = (void *) connection.data;
	if (mainrep->header.result) goto error;

	*numfiles=mainrep->numfiles;

	size = (*numfiles)*(sizeof(struct afp_file_info_basic));

	*data = malloc(size);

	memcpy(*data,((void *) mainrep) + 
		sizeof(struct afp_server_readdir_response), size);

	if ((mainrep->eod) && (eod)) *eod=1;

	return 0;

error:
	return -1;
}


int afp_sl_getvols(struct afp_url * url, unsigned int start,
	unsigned int count, unsigned int * numvols,
	struct afp_volume_summary * vols)
{

	struct afp_server_getvols_request req;
	int ret;
	struct afp_server_getvols_response * response;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	req.header.close=1;
	req.header.len = sizeof(struct afp_server_getvols_request);
	req.header.command=AFP_SERVER_COMMAND_GETVOLS;
	req.start=start;
	req.count=count;
	memcpy(&req.url,url,sizeof(*url));

	send_command(sizeof(req),(char *) &req,AFP_SERVER_COMMAND_GETVOLS);

	ret=read_answer();

	response = connection.data;

	memcpy(vols, 
		((void *)response) + sizeof(struct afp_server_getvols_response),
		response->num * sizeof(struct afp_volume_summary));

	*numvols = response->num;

	return response->header.result;
}


int afp_sl_resume(const char * servername)
{
	struct afp_server_resume_request req;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	req.header.close=1;
	req.header.len=sizeof(struct afp_server_resume_request);
	req.header.command=AFP_SERVER_COMMAND_RESUME;

	snprintf(req.server_name,AFP_SERVER_NAME_LEN,"%s",servername);

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_RESUME);

	return read_answer();
}

int afp_sl_suspend(const char * servername)
{
	struct afp_server_suspend_request req;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	req.header.close=1;
	req.header.len =sizeof(struct afp_server_suspend_request);
	req.header.command=AFP_SERVER_COMMAND_SUSPEND;

	snprintf(req.server_name,AFP_SERVER_NAME_LEN,servername);

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_SUSPEND);

	return read_answer();
}

int afp_sl_unmount(const char * volumename)
{
	struct afp_server_unmount_request req;
	struct afp_server_unmount_response * resp;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	req.header.close=1;
	req.header.len =sizeof(struct afp_server_unmount_request);
	req.header.command=AFP_SERVER_COMMAND_UNMOUNT;

	snprintf(req.name,AFP_VOLUME_NAME_UTF8_LEN,volumename);

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_UNMOUNT);

	ret = read_answer();
	resp = connection.data;

	if (connection.len<sizeof (struct afp_server_unmount_response)) 
		return 0;

	if (connection.print) {
		connection.print(resp->unmount_message);
	}

	return resp->header.result;
}


/* 
 *
 * afp_sl_connect(,&error)
 *
 * Sets error to:
 * 0:
 *      No error
 * -ENONET: 
 *      could not get the address of the server
 * -ENOMEM: 
 *      could not allocate memory
 * -ETIMEDOUT: 
 *      timed out waiting for connection
 * -ENETUNREACH:
 *      Server unreachable
 * -EISCONN:
 *      Connection already established
 * -ECONNREFUSED:
 *     Remote server has refused the connection
 * -EACCES, -EPERM, -EADDRINUSE, -EAFNOSUPPORT, -EAGAIN, -EALREADY, -EBADF,
 * -EFAULT, -EINPROGRESS, -EINTR, -ENOTSOCK, -EINVAL, -EMFILE, -ENFILE, 
 * -ENOBUFS, -EPROTONOSUPPORT:
 *     Internal error
 *
 * Returns:
 * 0: No error
 * -1: An error occurred
 */

int afp_sl_connect(struct afp_url * url, unsigned int uam_mask, 
	serverid_t *id, char * loginmesg, int * error)
{
	struct afp_server_connect_request req;
	struct afp_server_connect_response *resp;
	char * t;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}
	req.header.close=0;
	req.header.len =sizeof(struct afp_server_connect_request);
	req.header.command=AFP_SERVER_COMMAND_CONNECT;

	memcpy(&req.url,url,sizeof(struct afp_url));
	req.uam_mask=uam_mask;

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_CONNECT);

	ret=read_answer();

	resp = connection.data;

	if (connection.len<=sizeof (struct afp_server_connect_response)) 
		return 0;

	t = connection.data + sizeof(struct afp_server_connect_response);

	if (connection.print) {
		connection.print(t);
	}

	if (loginmesg) 
		memcpy(loginmesg,resp->loginmesg,AFP_LOGINMESG_LEN);

	if (error) *error=resp->connect_error;

	if (resp->header.result==0) {
		return 0;
	} else {
		return resp->connect_error;
	}
}

int afp_sl_attach(struct afp_url * url, unsigned int volume_options,
	volumeid_t * volumeid)
{
	struct afp_server_attach_request req;
	struct afp_server_attach_response * response;
	char * t;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	response = (void *) connection.data;

	req.header.close=1;
	req.header.len =sizeof(struct afp_server_attach_request);
	req.header.command=AFP_SERVER_COMMAND_ATTACH;

	memcpy(&req.url,url,sizeof(struct afp_url));
	req.volume_options = volume_options;

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_ATTACH);

	ret=read_answer();

	if (connection.len!=sizeof (struct afp_server_attach_response)) 
		return 0;

	t = connection.data + sizeof(struct afp_server_attach_response);

	if (connection.print) {
		connection.print(t);
	}

	if (volumeid) 
		memcpy(volumeid,&response->volumeid,sizeof(volumeid_t));

	return ret;
}


int afp_sl_detach(volumeid_t *volumeid, struct afp_url * url)
{
	struct afp_server_detach_request req;
	char * t;
	int ret;
	volumeid_t tmpvolid;
	volumeid_t *volid_p = volumeid;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	if (volumeid==NULL) {
		ret=afp_sl_getvolid(url,&tmpvolid);
		if (ret) return ret;
		volid_p = &tmpvolid;
	}


	req.header.close=1;
	req.header.len =sizeof(struct afp_server_detach_request);
	req.header.command=AFP_SERVER_COMMAND_DETACH;

	memcpy(&req.volumeid,volid_p,sizeof(volumeid_t));

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_DETACH);

	ret=read_answer();

	if (connection.len<=sizeof (struct afp_server_detach_response)) 
		return 0;

	t = connection.data + sizeof(struct afp_server_detach_response);

	if (connection.print) {
		connection.print(t);
	}
	return ret;
}


/* afp_get_mountpoint
 *
 * Checks to see if the URL is already mounted and returns the mountpoint
 */

int afp_sl_get_mountpoint(struct afp_url * url, char * mountpoint)
{
	struct afp_server_get_mountpoint_request req;
	struct afp_server_get_mountpoint_response * response;
	char * t;
	int ret;

	req.header.close=1;
	req.header.len =sizeof(struct afp_server_get_mountpoint_request);
	req.header.command=AFP_SERVER_COMMAND_GET_MOUNTPOINT;

	memcpy(&req.url,url,sizeof(struct afp_url));

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_GET_MOUNTPOINT);

	ret=read_answer();

	if (connection.len!=sizeof (struct afp_server_get_mountpoint_response)) {
		ret = AFP_SERVER_RESULT_ERROR;
		goto done;
	}

	response=(void *) connection.data;

	ret=((struct afp_server_response_header *) connection.data)->result;

	if (ret==AFP_SERVER_RESULT_OKAY) {

	printf("slgm10: %s\n",response->mountpoint);
		memcpy(mountpoint,response->mountpoint,PATH_MAX );
	}
done:
	return ret;
}

int afp_sl_mount(struct afp_url * url, const char * mountpoint, 
	const char * map, unsigned int volume_options)
{
	struct afp_server_mount_request req;
	char * t;
	int ret;

	req.header.close=1;
	req.header.len =sizeof(struct afp_server_mount_request);
	req.header.command=AFP_SERVER_COMMAND_MOUNT;

	memcpy(&req.url,url,sizeof(struct afp_url));
	snprintf(req.mountpoint,PATH_MAX,mountpoint);
	if (map) req.map=map_string_to_num(map);
		else req.map=AFP_MAPPING_UNKNOWN;
	req.volume_options = volume_options;
	req.changeuid=changeuid;

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_MOUNT);

	ret=read_answer();

	if (connection.len<=sizeof (struct afp_server_mount_response)) 
		return 0;

	t = connection.data + sizeof(struct afp_server_mount_response);

	if (connection.print) {
		connection.print(t);
	}

	return ret;
}


int afp_sl_setup(void)
{
	afp_sl_conn_setup();

	return daemon_connect(geteuid());
}

int afp_sl_setup_diffuser(unsigned int uid, unsigned int gid)
{
	return -1;
	
}

int afp_sl_serverinfo(struct afp_url * url, struct afp_server_basic * basic)
{
	struct afp_server_serverinfo_request req;
	struct afp_server_serverinfo_response *response;
	char * t;
	int ret;

	if (afp_sl_setup()) {
		return AFP_SERVER_RESULT_AFPFSD_ERROR;
	}

	response=(void *) connection.data;

	req.header.close=1;
	req.header.len =sizeof(struct afp_server_serverinfo_request);
	req.header.command=AFP_SERVER_COMMAND_SERVERINFO;

	memcpy(&req.url,url,sizeof(struct afp_url));

	send_command(sizeof(req),(char *)&req,AFP_SERVER_COMMAND_SERVERINFO);

	ret=read_answer();

	if (connection.len<sizeof (struct afp_server_serverinfo_response)) {
		return 0;
	}

	memcpy(basic, &response->server_basic, sizeof(struct afp_server_basic));

	return ret;
}



