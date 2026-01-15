#include <errno.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>


#include "afp.h"
#include "uams_def.h"
#include "map_def.h"
#include "afpfsd.h"
#include "libafpclient.h"
#include "afpsl.h"

static void usage(void) 
{
	printf("usage\n");
}

int do_stat(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	struct stat stat;
	int ret;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);
	afp_default_url(&url);
	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}

	ret = afp_sl_stat(NULL,NULL,&url,&stat);

	switch(ret) {
	case AFP_SERVER_RESULT_AFPFSD_ERROR:
                printf("Could not setup connection to afpfsd\n");
                return -1;
	case AFP_SERVER_RESULT_OKAY:
		break;
	case AFP_SERVER_RESULT_NOTCONNECTED:
		printf("Not connected\n");
		return -1;
	case AFP_SERVER_RESULT_NOTATTACHED:
		printf("Not attacheded\n");
		return -1;
	case AFP_SERVER_RESULT_ENOENT:
		printf("File does not exist\n");
		return -1;
	default:
		printf("Unknown error\n");
	}

	printf("mode: %o\n",stat.st_mode);

	return ret;
}

int do_get(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	int ret;
	unsigned int received;
	unsigned long long total=0;
	#define GET_DATA_SIZE 2048
	char data[GET_DATA_SIZE];
	unsigned int eof;
	unsigned int fileid;
	unsigned int mode=0;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);
	afp_default_url(&url);
	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}


	volumeid_t volid;

	ret=afp_sl_getvolid(&url,&volid);
        if (ret==AFP_SERVER_RESULT_AFPFSD_ERROR) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	if (ret) goto done;

	ret=afp_sl_open(NULL,NULL,&url,&fileid,mode);
	if (ret) goto done;
	
	while (eof==0) {

		ret=afp_sl_read(&volid,fileid,0, /* data, not resource */
			total, GET_DATA_SIZE,&received,&eof,data);

		total+=received;

		if (ret!=AFP_SERVER_RESULT_OKAY) goto done;

		printf("%s",data);

	}

done:
	if (fileid) {
		afp_sl_close(&volid,fileid);
	}
	return ret;
}
int do_readdir(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	int ret;
	unsigned int numfiles;
	char * data;
	struct afp_file_info_basic * fpb;
	int i;
	unsigned int totalfiles=0;
	int eod;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);
	afp_default_url(&url);
	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}

	while (1) {

		ret=afp_sl_readdir(NULL,NULL,&url,totalfiles,10,
			&numfiles,&data,&eod);
		if (ret==AFP_SERVER_RESULT_AFPFSD_ERROR) {
			printf("Could not setup connection to afpfsd\n");
			return -1;
		}

		if (ret!=AFP_SERVER_RESULT_OKAY) goto error;

		fpb=data;
		for (i=0;i<numfiles;i++) {
			printf("name: %s\n",fpb->name);
			fpb=((void *) fpb) + sizeof(struct afp_file_info_basic);
		}
		free(data);
		if (eod) break;
		totalfiles+=numfiles;
	}

	return ret;

error:
	printf("Could not readdir\n");
	return -1;
}

int do_getvols(int argc, char * argv[])
{
	int ret;
	char url_string[1024];
	struct afp_url url;
	int i;
#define EXTRA_NUM_VOLS 10
	char data[EXTRA_NUM_VOLS * AFP_VOLUME_NAME_UTF8_LEN];
	unsigned int num;
	char * name;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);
	afp_default_url(&url);
	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}

	ret = afp_sl_getvols(&url,0,10,&num,data);

	switch(ret) {
	case AFP_SERVER_RESULT_AFPFSD_ERROR:
                printf("Could not setup connection to afpfsd\n");
                return -1;

	case AFP_SERVER_RESULT_OKAY:
		break;
	case AFP_SERVER_RESULT_NOTCONNECTED:
		printf("Not connected\n");
		return -1;
	}

	for (i=0;i<num;i++) {
		name = data + (i*AFP_VOLUME_NAME_UTF8_LEN);
		printf("name: %s\n",name);
	}

	if (ret<0) return 0;

}

int do_serverinfo(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	int ret;
	struct afp_server_basic server_basic;

	if (argc!=3) {
		usage();
		return -1;
	}

	snprintf(url_string,1024,argv[2]);
	afp_default_url(&url);

	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}


	if((ret=afp_sl_serverinfo(&url,&server_basic))==0) {
		printf("Server name: %s\n",server_basic.server_name_printable);
	} else if (ret==AFP_SERVER_RESULT_AFPFSD_ERROR) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	return ret;

}
int do_getvolid(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	unsigned int uam_mask=default_uams_mask();
	int ret;
	int i;
	volumeid_t volumeid;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);

	afp_default_url(&url);

	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}

	ret=afp_sl_getvolid(&url,&volumeid);

	if (ret==AFP_SERVER_RESULT_AFPFSD_ERROR) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }


	printf("%p\n",(void *) volumeid);

	return ret;

}

int do_attach(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	unsigned int uam_mask=default_uams_mask();
	int ret;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);

	afp_default_url(&url);

	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}


	ret=afp_sl_attach(&url,NULL,NULL);

	if (ret==AFP_SERVER_RESULT_AFPFSD_ERROR) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }
	return ret;
}

int do_detach(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	int ret;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);
	afp_default_url(&url);
	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}

	ret=afp_sl_detach(NULL,&url);
	if (ret==AFP_SERVER_RESULT_AFPFSD_ERROR) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }


	return ret;
}


int do_connect(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	unsigned int uam_mask=default_uams_mask();
	int ret;

	if (argc!=3) {
		usage();
		return -1;
	}
	snprintf(url_string,1024,argv[2]);

	afp_default_url(&url);

	if (afp_parse_url(&url,url_string,1)!=0) {
		printf("Could not parse url\n");
		return -1;
	}


	ret=afp_sl_connect(&url,uam_mask,NULL,NULL,NULL);

	if (ret==AFP_SERVER_RESULT_AFPFSD_ERROR) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	return ret;
}


int main(int argc, char *argv[]) 
{
	if (argc<2) {
		printf("Not enough arguments\n");
		return -1;
	}
	if (strncmp(argv[1],"connect",7)==0) 
		do_connect(argc,argv);
	else if (strncmp(argv[1],"attach",6)==0) 
		do_attach(argc,argv);
	else if (strncmp(argv[1],"detach",6)==0) 
		do_detach(argc,argv);
	else if (strncmp(argv[1],"readdir",7)==0) 
		do_readdir(argc,argv);
	else if (strncmp(argv[1],"getvols",7)==0) 
		do_getvols(argc,argv);
	else if (strncmp(argv[1],"stat",4)==0) 
		do_stat(argc,argv);
	else if (strncmp(argv[1],"getvolid",8)==0) 
		do_getvolid(argc,argv);
	else if (strncmp(argv[1],"get",3)==0) 
		do_get(argc,argv);
	else if (strncmp(argv[1],"serverinfo",10)==0) 
		do_serverinfo(argc,argv);
	else {
		usage();
		goto done;
	}

done:
	return 0;

}

