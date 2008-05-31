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


printf("\n\nEXECING\n\n");


		execvp(filename,argv);
		
		printf("done threading\n");
	}
	return 0;
}

static int setup_shmem(struct afpfsd_connect * conn)
{
	key_t key = AFPFSD_SHMEM_KEY;
	int shmid;
	char * shm;

	if ((shmid = shmget(key, AFPFSD_SHMEM_SIZE, IPC_CREAT | 0666)) < 0) {
		perror("shmget");
		return -1;
	}

	if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
		perror("shmat");
		return -1;
	}

	conn->shmem=shm;


}


int daemon_connect(struct afpfsd_connect * conn, unsigned int uid) 
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
printf("Ret from connect: %d\n",ret);
perror("connect");

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
	conn->fd=sock;
	setup_shmem(conn);
	return 0;
}

static int read_answer(struct afpfsd_connect * conn) {
	unsigned int expected_len=0, packetlen;
	struct timeval tv;
	fd_set rds,ords;
	int ret;
	struct afp_server_response_header * answer = (void *) conn->data;

	memset(conn->data,0,MAX_CLIENT_RESPONSE);
	conn->len=0;

	FD_ZERO(&rds);
	FD_SET(conn->fd,&rds);
	while (1) {
		tv.tv_sec=30; tv.tv_usec=0;
		ords=rds;
printf("about to select\n");
		ret=select(conn->fd+1,&ords,NULL,NULL,&tv);
printf("out of ret, %d\n",ret);
		if (ret==0) {
			printf("No response from server, timed out.\n");
			return -1;
		}
		if (FD_ISSET(conn->fd,&ords)) {
			packetlen=read(conn->fd,conn->data+conn->len,
				MAX_CLIENT_RESPONSE-conn->len);
			if (packetlen<=0) {
				printf("Dropped connection\n");
				goto done;
			}
			if (conn->len==0) {  /* This is our first read */
				expected_len=
					((struct afp_server_response_header *) 
					conn->data)->len;
			}
			conn->len+=packetlen;
			if (conn->len==expected_len)
				goto done;
			if (ret<0) goto error;

		}
	}

done:

	return ((struct afp_server_response_header *) conn->data)->result;

error:
	return -1;
}

static int send_command(struct afpfsd_connect * conn, 
	unsigned int len, char * data)
{
	int ret;
	ret = write(conn->fd,data,len);
printf("Wrote %d on %d\n",ret,conn->fd);
	return  ret;
}

static void conn_print(const char * text) 
{
	printf(text);
}

void afp_sl_conn_setup(struct afpfsd_connect * conn)
{


	conn->print=conn_print;


}


int afp_sl_exit(struct afpfsd_connect * conn)
{
	struct afp_server_exit_request req;
	req.header.command=AFP_SERVER_COMMAND_EXIT;
	req.header.len=sizeof(req);
	send_command(conn,sizeof(req),(char *) &req);

	return read_answer(conn);
}

int afp_sl_status(struct afpfsd_connect * conn, 
	const char * volumename, const char * servername,
	char * text, unsigned int * remaining)
{
	struct afp_server_status_request req;
	struct afp_server_status_response * resp;
	int ret;
	req.header.command=AFP_SERVER_COMMAND_STATUS;
	req.header.len=sizeof(req);

	if (volumename) snprintf(req.volumename,AFP_VOLUME_NAME_LEN,
		volumename);
	if (servername) snprintf(req.servername,AFP_SERVER_NAME_LEN,
		servername);

	send_command(conn,sizeof(req),(char *)&req);

	*remaining-=conn->len;

	ret=read_answer(conn);

	snprintf(text,conn->len,conn->data+
		sizeof(struct afp_server_status_response));

	return ret;
}

int afp_sl_getvolid(struct afpfsd_connect * conn, 
	struct afp_url * url, volumeid_t *volid)
{
	struct afp_server_getvolid_request req;
	struct afp_server_getvolid_response * reply;
	int ret;

	req.header.len = sizeof(struct afp_server_getvolid_request);
	req.header.command=AFP_SERVER_COMMAND_GETVOLID;

	memcpy(&req.url,url,sizeof(*url));

	send_command(conn,sizeof(req),(char *)&req);

	if ((ret=read_answer(conn))) 
		return -1;

	reply = (void *) conn->data;

	memcpy(volid,&reply->volumeid,sizeof(volumeid_t));

	return 0;

}

int afp_sl_readdir(struct afpfsd_connect * conn, 
	volumeid_t * volid, const char * path, struct afp_url * url,
	int start, int count, unsigned int * numfiles, char ** data)
{
	struct afp_server_readdir_request req;
	struct afp_server_readdir_response * mainrep;
	int ret;
	char * mainresp;
	char * tmppath = path;
	volumeid_t * volid_p = volid;
	volumeid_t tmpvolid;

	req.header.len = sizeof(struct afp_server_readdir_request);
	req.header.command=AFP_SERVER_COMMAND_READDIR;
	req.start=start;
	req.count=count;

	if (volid==NULL) {
		if (afp_sl_getvolid(conn,url,&tmpvolid)) 
			return -1;
		tmppath=url->path;
		volid_p = &tmpvolid;
	}

	memcpy(&req.volumeid,volid_p, sizeof(volumeid_t));
	memcpy(req.path,tmppath,AFP_MAX_PATH);

	send_command(conn,sizeof(req),(char *)&req);

	ret=read_answer(conn);

	mainrep = (void *) conn->data;
	*numfiles=mainrep->numfiles;

	*data = malloc((*numfiles)*(sizeof(struct afp_file_info)));

	memcpy(*data,mainrep + sizeof(struct afp_file_info), 
		(*numfiles)*sizeof(struct afp_file_info));

	printf("num: %d\n",mainrep->numfiles);

	return 0;
}

int afp_sl_resume(struct afpfsd_connect * conn, const char * servername)
{
	struct afp_server_resume_request req;
	req.header.len=sizeof(struct afp_server_resume_request);
	req.header.command=AFP_SERVER_COMMAND_RESUME;

	snprintf(req.server_name,AFP_SERVER_NAME_LEN,"%s",servername);

	send_command(conn,sizeof(req),(char *)&req);

	return read_answer(conn);
}

int afp_sl_suspend(struct afpfsd_connect * conn, const char * servername)
{
	struct afp_server_suspend_request req;
	req.header.len =sizeof(struct afp_server_suspend_request);
	req.header.command=AFP_SERVER_COMMAND_SUSPEND;

	snprintf(req.server_name,AFP_SERVER_NAME_LEN,servername);

	send_command(conn,sizeof(req),(char *)&req);

	return read_answer(conn);
}

int afp_sl_unmount(struct afpfsd_connect * conn, const char * volumename)
{
	struct afp_server_unmount_request req;
	struct afp_server_unmount_response * resp;
	int ret;

	req.header.len =sizeof(struct afp_server_unmount_request);
	req.header.command=AFP_SERVER_COMMAND_UNMOUNT;

	snprintf(req.name,AFP_VOLUME_NAME_LEN,volumename);

	send_command(conn,sizeof(req),(char *)&req);

	ret = read_answer(conn);
	resp = conn->data;

	if (conn->len<sizeof (struct afp_server_unmount_response)) 
		return 0;

	if (conn->print) {
		conn->print(resp->unmount_message);
	}

	return resp->header.result;
}

int afp_sl_connect(struct afpfsd_connect * conn, 
	struct afp_url * url, unsigned int uam_mask, 
	serverid_t *id)
{
	struct afp_server_connect_request req;
	struct afp_server_connect_response *resp;
	char * t;
	int ret;

	req.header.len =sizeof(struct afp_server_connect_request);
	req.header.command=AFP_SERVER_COMMAND_CONNECT;

	memcpy(&req.url,url,sizeof(struct afp_url));
	req.uam_mask=uam_mask;

printf("Sending connect\n");
	send_command(conn,sizeof(req),(char *)&req);
printf("Done sending for connect\n");


	ret=read_answer(conn);
printf("done reading for connect\n");

	resp = conn->data;

	if (conn->len<=sizeof (struct afp_server_connect_response)) 
		return 0;

	t = conn->data + sizeof(struct afp_server_connect_response);

	if (conn->print) {
		conn->print(t);
	}

	return resp->header.result;
}

int afp_sl_attach(struct afpfsd_connect * conn, 
	struct afp_url * url, unsigned int volume_options)
{
	struct afp_server_attach_request req;
	char * t;
	int ret;

	req.header.len =sizeof(struct afp_server_attach_request);
	req.header.command=AFP_SERVER_COMMAND_ATTACH;

	memcpy(&req.url,url,sizeof(struct afp_url));
	req.volume_options = volume_options;

	send_command(conn,sizeof(req),(char *)&req);

	ret=read_answer(conn);

	if (conn->len<=sizeof (struct afp_server_attach_response)) 
		return 0;

	t = conn->data + sizeof(struct afp_server_attach_response);

	if (conn->print) {
		conn->print(t);
	}

	return ret;
}

int afp_sl_detach(struct afpfsd_connect * conn, 
	volumeid_t *volumeid, struct afp_url * url)
{
	struct afp_server_detach_request req;
	char * t;
	int ret;
	volumeid_t tmpvolid;
	volumeid_t *volid_p = volumeid;


	if (volumeid==NULL) {
		if (afp_sl_getvolid(conn,url,&tmpvolid)) 
			return -1;
		volid_p = &tmpvolid;
	}


	req.header.len =sizeof(struct afp_server_detach_request);
	req.header.command=AFP_SERVER_COMMAND_DETACH;

	memcpy(&req.volumeid,volid_p,sizeof(volumeid_t));

	send_command(conn,sizeof(req),(char *)&req);

	ret=read_answer(conn);

	if (conn->len<=sizeof (struct afp_server_detach_response)) 
		return 0;

	t = conn->data + sizeof(struct afp_server_detach_response);

	if (conn->print) {
		conn->print(t);
	}
	return ret;
}


int afp_sl_mount(struct afpfsd_connect * conn, 
	struct afp_url * url, const char * mountpoint, 
	const char * map, unsigned int volume_options)
{
	struct afp_server_mount_request req;
	char * t;
	int ret;

	req.header.len =sizeof(struct afp_server_mount_request);
	req.header.command=AFP_SERVER_COMMAND_MOUNT;

	memcpy(&req.url,url,sizeof(struct afp_url));
	snprintf(req.mountpoint,PATH_MAX,mountpoint);
	if (map) req.map=map_string_to_num(map);
		else req.map=AFP_MAPPING_UNKNOWN;
	req.volume_options = volume_options;
	req.changeuid=changeuid;

printf("Sending mount\n");
	send_command(conn,sizeof(req),(char *)&req);

printf("About to read answer for mount\n");
	ret=read_answer(conn);
printf("Done reading answer for mount\n");

	if (conn->len<=sizeof (struct afp_server_mount_response)) 
		return 0;

	t = conn->data + sizeof(struct afp_server_mount_response);

	if (conn->print) {
		conn->print(t);
	}

	return ret;
}


int afp_sl_setup(struct afpfsd_connect * conn) 
{
	afp_sl_conn_setup(conn);

	return daemon_connect(conn,geteuid());
}

int afp_sl_setup_diffuser(struct afpfsd_connect * conn, 
	unsigned int uid, unsigned int gid)
{
	return -1;
	
}



