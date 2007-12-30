
#include <string.h>
#include <stdio.h>
#include "afp.h"

/* This is wildly incomplete */


void afp_default_url(struct afp_url *url)
{
printf("size: %d\n",sizeof(*url));
	memset(url,0,sizeof(*url));
	url->protocol=TCPIP;
	url->port=548;
}

static int check_servername (char * servername) 
{
	return 0;
}

static int check_port(char * port) 
{
	return 0;
}

static int check_uamname(char * uam) 
{
	return 0;
}

static int check_username(char * user) 
{
	return 0;
}

static int check_password(char * user) 
{
	return 0;
}

void afp_print_url(struct afp_url * url)
{

printf("servername: %s\n"
"volumename: %s\n"
"path: %s\n"
"username: %s\n"
"password: %s\n"
"port: %d\n"
"uam name: %s\n",
	url->servername,
	url->volumename,
	url->path,
	url->username,
	url->password,
	url->port,url->uamname);

}

int afp_parse_url(struct afp_url * url, char * toparse, int verbose)
{
	struct afp_url tmp_url;
	char firstpart[255],secondpart[2048];
	char *p, *q;
	int volumenamelen;
	int pathlen;
	int servernamelen;
	int firstpartlen;
	int skip_earliestpart=0;
	int skip_secondpart=0;
	char * lastchar;

	if (verbose) printf("Parsing %s\n",toparse);

	/* The most complex URL is:
 
	afp://user;AUTH=authType:password@server-name:port/volume-name/path 

	where the optional parms are user, password, AUTH and port, so the
	simplest is:

	afp://server-name/volume-name/path 

	*/

	/* if there is a ://, make sure it is preceeded by afp */

	if ((p=strstr(toparse,"://"))!=NULL) {
		q=p-3;
		if (p<toparse) {
			if (verbose) printf("URL does not start with afp://\n");
			return -1;
		}

		if (strncmp(q,"afp",3)!=0) {
			if (verbose) printf("URL does not start with afp://\n");
			return -1;
		}
		p+=3;
	} 
	if (p==NULL) p=toparse;

	/* Now split on the first / */

	if (sscanf(p,"%[^'/']/%[^'\']",
		firstpart, secondpart)!=2) {
		/* Okay, so there's no volume. */
		skip_secondpart=1;
	}

	firstpartlen=strlen(firstpart);

	lastchar=firstpart+firstpartlen-1;

	/* First part could be something like:
		user;AUTH=authType:password

	   We'll assume that the breakout is:
                user;  optional user name
	        AUTH=authtype:
	*/

	/* Let's see if there's a ';'.  q is the end of the username */

	if ((p=strchr(firstpart,'@'))) {
		*p='\0';
		p++; 
	} else {
		skip_earliestpart=1;
		p=firstpart;
	}
	/* p now points to the start of the server name*/

	/* see if we have a port number */

	if ((q=strchr(p,':'))) {
		*q='\0';
		q++;
		if ((url->port=atoi(q))==0) {
			if (verbose) printf("Port appears to be zero\n");
			return -1;
		}
	}

	memcpy(url->servername,p,strlen(p));
	if (check_servername(url->servername)) {
			if (verbose) printf("This isn't a valid servername\n");
			return -1;
	}

	if ((p==NULL) || ((strlen(p)+p-1)==lastchar)) {
		/* afp://server */
		goto done;
	}

	if ((q) && ((strlen(q)+q-1)==lastchar)) {
		/* afp://server:port */
		goto done;
	}


earliest_part:

	if (skip_earliestpart) {
		p+=strlen(p);
		goto parse_secondpart;
	}
	p=firstpart;

	/* Now we're left with something like user[;AUTH=uamname][:password] */

	/* Look for :password */

	if ((q=strrchr(p,':'))) {
		*q='\0';
		q++;
		memcpy(url->password,q,strlen(q));
		if (check_password(url->password)) {
			if (verbose) printf("This isn't a valid passwd\n");
			return -1;
		}
	}

	/* Now we're down to user[;AUTH=uamname] */
	p=firstpart;

	if ((q=strstr(p,";AUTH="))) {
		*q='\0';
		q+=6;
		memcpy(url->uamname,q,strlen(q));
		if (check_uamname(url->uamname)) {
			if (verbose) printf("This isn't a valid uamname\n");
			return -1;
		}
	}

	if (strlen(p)) {
		memcpy(url->username,p,strlen(p));
		if (check_username(url->username)) {
			if (verbose) printf("This isn't a valid username\n");
			return -1;;
		}
	}

	if (skip_secondpart) goto done;

parse_secondpart:

	if (secondpart[strlen(secondpart)]=='/') 
		secondpart[strlen(secondpart)]='\0';

	p=secondpart;
	if ((q=strchr(p,'/'))) {
		*q='\0';
		q++;
	}
	memcpy(url->volumename,p,strlen(p));


	if (q) {
		url->path[0]='/';
		memcpy(url->path+1,q,strlen(q));
	}

done:
	if (verbose) printf("Successful parsing of URL\n");
	return 0;
}
