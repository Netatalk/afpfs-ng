#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#include "afp.h"

struct afp_user {
	unsigned int hostid;
	unsigned int serverid;
	unsigned char isuid;
	struct afp_user * next;
};

static void user_add(struct afp_server * server, unsigned char isuid,
	unsigned int hostid,unsigned int serverid)
{
	struct afp_user * u, *newu;

	for (u=server->user_base;u;u=u->next) {
		if ((u->hostid==hostid) && (u->isuid==isuid)) {
			u->isuid=isuid;
			u->serverid=serverid;
			return;
		}
	}

	newu=malloc(sizeof(struct afp_user));
	newu->hostid=hostid; newu->serverid=serverid;
	newu->isuid=isuid;
	newu->next=NULL;
	if (server->user_base==NULL) server->user_base=newu;
	else {
		for (u=server->user_base;u->next;u=u->next);
		u->next=newu;
	}
}

void user_deleteall(struct afp_server * server)
{
	struct afp_user * u, * next;

	for (u=server->user_base;u;u=next) {
		next=u->next;
		free(u);
	}
	server->user_base=NULL;
}

int user_findbyserverid(struct afp_server * server, unsigned char isuid,
	unsigned int serverid, unsigned int *hostid)
{
	struct afp_user * u;
	struct passwd * pwd;
	struct group * grp;
	char name[255];
	for (u=server->user_base;u;u=u->next) {
		if ((u->isuid==isuid) && (u->serverid==serverid)) {
			if (hostid) *hostid=u->hostid;
			return 0;
		}
	}

	/* Okay, so it isn't in our cache */

	/* Get the name for the id on the server */

	if (afp_mapid_request(server,
		(isuid ? kUTF8NameToUserID : kUTF8NameToGroupID ),
		serverid,name)!=kFPNoErr) return -1;

	/* Convert that to a host id */

	if (isuid) {
		if ((pwd = getpwnam(name))==NULL) return -1;
		*hostid=pwd->pw_uid;
	} else {
		if ((grp = getgrnam(name))==NULL) return -1;
		*hostid=grp->gr_gid;
	}
	/* Add it to our cache */
	user_add(server,isuid,*hostid,serverid);

	return 0;
}

int user_findbyhostid(struct afp_server * server, unsigned char isuid,
	unsigned int hostid, unsigned int *serverid)
{
	struct afp_user * u;
	struct passwd * pwd;
	struct group * grp;
	char * name;
	for (u=server->user_base;u;u=u->next) {
		if ((u->isuid==isuid) && (u->hostid==hostid)) {
			if (serverid) *serverid=u->serverid;
			return 0;
		}
	}

	if (isuid) {
		if ((pwd = getpwuid(hostid))==NULL) return -1;
		name=pwd->pw_name;
	} else {
		if ((grp = getgrgid(hostid))==NULL) return -1;
		name=grp->gr_name;
	}

	if (afp_mapname_request(server, 
		(isuid ? kUTF8NameToUserID : kUTF8NameToGroupID ),
		name,(void *) serverid)!=kFPNoErr) return -1;

	/* Add it to our cache */
	user_add(server,isuid,hostid,*serverid);

	return 0;
}


/* Figure out how we should map local UIDs to server UIDs */
/* This is described on p.20 in the description for kNoNetworkUserIDs */

int afp_find_maptype(struct afp_volume * volume)
{

	if (volume->attributes & kNoNetworkUserIDs) {
		volume->map_type= afp_map_byname; 
		return 0;
	}
#if 0
	switch (afp_getuserinfo(volume->server, 0, 1 /* this userid */ ,&newuserid)) {


	}

	if (newuser==getuid()) ;

#endif
	return 0;
	


}

