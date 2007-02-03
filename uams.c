/*
 *  uams.c
 *
 *  Copyright (C) 2006 Alex deVries
 *
 */

#ifdef HANDLE_RANDNUM
#include <des.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include "dsi.h"
#include "afp.h"
#include "utils.h"
#include "log.h"
#include "uams_def.h"

struct afp_uam{
	unsigned int bitmap;
	char name[AFP_UAM_LENGTH];
        int (*create_auth_info)(char * username, char * password, char **authinfo);
        int (*login)(struct afp_server * server);
	struct afp_uam * next;
};

static struct afp_uam * uam_base = NULL;

static int noauth_authinfo(char * username, char * passwd, char **info);
static int cleartxt_authinfo(char * username, char * passwd, char **info);
static struct afp_uam uam_noauth = 
	{UAM_NOUSERAUTHENT,"No User Authent",&noauth_authinfo,NULL,NULL};
static struct afp_uam uam_cleartxt = 
	{UAM_CLEARTXTPASSWRD,"Cleartxt Passwrd",&cleartxt_authinfo,NULL,NULL};


static int register_uam(struct afp_uam * uam) 
{

	struct afp_uam * u = uam_base;
	if ((uam->bitmap=uam_string_to_bitmap(uam->name))==0) goto error;
	if (!uam_base)  {
		uam_base=uam;
		u=uam;
	} else {
		for (;u->next;u=u->next);
		u->next=uam;
	}
	uam->next=NULL;
	return 0;
error:
	LOG(AFPFSD,LOG_WARNING,
		"Could not register all UAMs\n");
	return -1;
}

static struct afp_uam * find_uam_by_bitmap(unsigned int i)
{
	struct afp_uam * u=uam_base;
	for (;u;u=u->next)
		if (u->bitmap==i)
			return u;
	return NULL;
}


int init_uams(void) {
	register_uam(&uam_cleartxt);
	register_uam(&uam_noauth);
	return 0;

}

static int cleartxt_authinfo(char * username, char * passwd, char **info) 
{
	char * p, *m;
	int passwdlen=strlen(passwd);
	int len=strlen(username)+1+8+1;

	if((m=malloc(len))==NULL) 
		return -1;
	bzero(m,len);

	p = m;
	p +=copy_to_pascal(p,username)+1;
	if (((uint64_t) p) & 0x1) len--;
                        else p++;
	if (passwdlen>8) passwdlen=8;
	bcopy(passwd,p,passwdlen);

	*info=m;
	return len;
}

static int noauth_authinfo(char * username, char * passwd, char **info)
{
	*info=NULL;
	return 0;
}

#ifdef HANDLE_RANDNUM

static int handle_randnum(char * passwd) 
{
	uint64_t seskey;
	char passwd[255];
	Key_schedule  seskeysched;

	memset(seskey, 0, sizeof(seskey))
	/* Call FPLogin or FPLoginExt, get random number */

	/* Check return code is kFPAuthContinue */

	/* Encrypt user password using DES */

	key_sched((C_Block *) seskey, seskeysched);
	memset(seskey, 0, sizeof(seskey));

	ecb_encrypt((C_Block *) seskey, (C_Block *) passwd,
		seskeysched, DES_ENCRYPT);

	/* Call FPLoginCont */
	
	
}

#endif


int afp_dologin(struct afp_server *server, 
		unsigned int uam, char * username, char * passwd)
{

	int ret;
	int passwdlen=strlen(passwd);
	char * authinfo=NULL;
	int len=0;
	struct afp_uam * u;
	char * uam_name = uam_bitmap_to_string(uam);

	if (!uam_name) {
		LOG(AFPFSD,LOG_WARNING,
			"Unknown uam string\n");
		return -1;
	}

	if ((u=find_uam_by_bitmap(uam))==NULL) {
		LOG(AFPFSD,LOG_WARNING,
			"Unknown uam\n");
		return -1;
	}

	if ((len=u->create_auth_info(username,passwd,&authinfo))<0) {
		if (authinfo) free(authinfo);
		return -1;
	}

	ret=afp_login(server,uam_name, authinfo,len);
	free(authinfo);
	return ret;

}

