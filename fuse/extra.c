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

int do_readdir(int argc, char * argv[])
{
	char url_string[1024];
	struct afp_url url;
	struct afpfsd_connect conn;
	int ret;
	unsigned int numfiles;
	char * data;
	struct afp_file_info * fp;
	int i;

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

	ret=afp_sl_readdir(&conn,NULL,NULL,&url,0,10,&numfiles,&data);

	fp=data;
	for (i=0;i<numfiles;i++) {
		printf("name: %s\n",fp->name);
		fp+=sizeof(struct afp_file_info);
	}

	return ret;
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
	else {
		usage();
		goto done;
	}

done:
	return 0;

}

