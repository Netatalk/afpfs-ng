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
	struct afpfsd_connect conn;
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

        if (afp_sl_setup(&conn)) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	ret = afp_sl_stat(&conn,NULL,NULL,&url,&stat);

	if (ret<0) return 0;

	printf("mode: %o\n",stat.st_mode);

	return ret;
}

int do_readdir(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	struct afpfsd_connect conn;
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

        if (afp_sl_setup(&conn)) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	while (1) {

		ret=afp_sl_readdir(&conn,NULL,NULL,&url,totalfiles,10,
			&numfiles,&data,&eod);
		if (ret<0) return 0;

		fpb=data;
		for (i=0;i<numfiles;i++) {
			printf("name: %s\n",fpb->name);
			fpb=((void *) fpb) + sizeof(struct afp_file_info_basic);
		}
		if (eod) break;
		totalfiles+=numfiles;
	}

	return ret;
}

int do_getvols(int argc, char * argv[])
{
	int ret;
	char url_string[1024];
	struct afpfsd_connect conn;
	struct afp_url url;
	int i;
#define EXTRA_NUM_VOLS 10
	char data[EXTRA_NUM_VOLS * AFP_VOLUME_NAME_LEN];
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

        if (afp_sl_setup(&conn)) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	ret = afp_sl_getvols(&conn,&url,0,10,&num,data);

	for (i=0;i<num;i++) {
		name = data + (i*AFP_VOLUME_NAME_LEN);
		printf("name: %s\n",name);
	}

	if (ret<0) return 0;

}

int do_attach(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	struct afpfsd_connect conn;
	unsigned int uam_mask=default_uams_mask();

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

        if (afp_sl_setup(&conn)) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	return afp_sl_attach(&conn,&url,NULL);

}

int do_detach(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	struct afpfsd_connect conn;

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

        if (afp_sl_setup(&conn)) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	return afp_sl_detach(&conn,NULL,&url);
}


int do_connect(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	struct afpfsd_connect conn;
	unsigned int uam_mask=default_uams_mask();

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

        if (afp_sl_setup(&conn)) {
                printf("Could not setup connection to afpfsd\n");
                return -1;
        }

	return afp_sl_connect(&conn,&url,uam_mask,NULL);

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
	else {
		usage();
		goto done;
	}

done:
	return 0;

}

