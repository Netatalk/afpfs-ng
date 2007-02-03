
#include <strings.h>
#include <string.h>
#include <linux/limits.h>
#include "afp.h"

#define appledouble ".AppleDouble"


int is_apple(char * path)
{
	char * p;
	int len=strlen(path);

	if (len<strlen(appledouble)) 
		return 0;
	p=path+len-strlen(appledouble);
	if (strstr(p,appledouble))
		return 1;
	else
		return 0;
}

int is_resource(struct afp_volume * volume, char * path) 
{
	char * p;
	if (!(volume->options & VOLUME_OPTION_APPLEDOUBLE))
		return 0;

	if ((p=strstr(path,appledouble))==NULL) 
		return 0;
	else return 1;
}

int apple_translate(struct afp_volume * volume, char * path) 
{

	char tmp[PATH_MAX];
	char * p, *p2, *start;
	int type;

	bzero(tmp,PATH_MAX);

	if (!(volume->options & VOLUME_OPTION_APPLEDOUBLE))
		return 0;

	if ((start=strstr(path,appledouble))==NULL) 
		return 0;

	if (strlen(start)==strlen(appledouble)) {
		/* We have just foo/.AppleDouble, nothing else */
		bzero(start,strlen(start));
		return AFP_RESOURCE_TYPE_PARENT1;
	}

	if ((p=strchr(start,'/'))==NULL) 
		return 0;

	if ((p2=strchr(p+1,'/'))==NULL)  {
		/* Here, we have foo/.AppleDouble/bar */
		bcopy(p+1,tmp,strlen(p+1));
		bzero(start,strlen(start));
		bcopy(tmp,start,strlen(tmp));
		return AFP_RESOURCE_TYPE_PARENT2;
	}

	/* And here, foo/.AppleDouble/bar/comment */

	if (strstr(p2,"comment")) 
		type=AFP_RESOURCE_TYPE_COMMENT;
	else if (strstr(p2,"finderinfo")) 
		type=AFP_RESOURCE_TYPE_FINDERINFO;
	else if (strstr(p2,"rsrc")) 
		type=AFP_RESOURCE_TYPE_RESOURCE;
	else return 0;

	bcopy(p+1,tmp,p2-p);
	bzero(start,strlen(start));
	bcopy(tmp,start,strlen(tmp)-1);

	return type;

}


