
#include <string.h>
#include <stdio.h>
#include "afp.h"

/* This is wildly incomplete */


void afp_default_url(struct afp_url *url)
{
	memset(url,'\0',sizeof(*url));
	url->protocol=TCPIP;
	url->port=548;
}

int afp_parse_url(struct afp_url * url, char * toparse)
{
	struct afp_url tmp_url;
	char firstpart[255],fullpath[2048];
	char *p, *q;
	int volumenamelen;
	int pathlen;
	int servernamelen;
	int firstpartlen;

	afp_default_url(url);

	/* The most complex URL is:
 
	afp://user;AUTH=authType:password@server-name:port/volume-name/path 

	where the optional parms are user, password, AUTH and port, so the
	simplest is:

	afp://server-name/volume-name/path 

	*/

	/* if there is a ://, make sure it is preceeded by afp */

	if ((p=strstr(toparse,"://"))!=NULL) {
		q=p-3;
		if (p<toparse) goto error;

		if (strncmp(q,"afp",3)!=0) goto error;
		p+=3;
	} 
	if (p==NULL) p=toparse;
printf("Now at %s\n",p);

	/* Now split on the first / */

	if (sscanf(p,"%[^'/']/%[^'\']",
		firstpart, fullpath)!=2) 
		goto error;

printf("first part: %s, second: %s\n",firstpart,fullpath);

	if (fullpath[strlen(fullpath)]=='/') 
		fullpath[strlen(fullpath)]='\0';

	/* First part could be something like:
		user;AUTH=authType:password
	*/

	/* Let's see if there's a ';' */

	p=firstpartlen;
	if ((q=strchr(p,';'))) {
		memcpy(url->username,p,q-p-1);
		p=q+1;
	}

	q=strchr(fullpath,'/');
	if (q) 
		volumenamelen=q-fullpath;
	else 
		volumenamelen=strlen(fullpath);
printf("q: %p len: %d\n",q,volumenamelen);

	pathlen=strlen(fullpath)-volumenamelen;
	

	memcpy(url->volumename,fullpath,volumenamelen);
	memcpy(url->path,fullpath+volumenamelen,pathlen);

	return 0;
error:
	return -1;
}
