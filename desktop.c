
/*
 *  fork.c
 *
 *  Copyright (C) 2006 Alex deVries
 *
 */
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <syslog.h>

#include "dsi.h"
#include "afp.h"
#include "utils.h"
#include "afp_protocol.h"
#include "log.h"

/* closedt, addicon, geticoninfo, addappl, removeappl */

int afp_geticon(struct afp_volume * volume , unsigned int filecreator,
	unsigned int filetype, unsigned char icontype, 
	unsigned short length, struct afp_icon * icon)
{
	struct {
		struct dsi_header dsi_header __attribute__((__packed__));
		uint8_t command;
		uint8_t pad1;
		uint16_t dtrefnum ;
		uint32_t filecreator; 
		uint32_t filetype ;
		uint8_t icontype ;
		uint8_t pad2;
		uint16_t length ;
	} __attribute__((__packed__)) request_packet;
	dsi_setup_header(volume->server,&request_packet.dsi_header,DSI_DSICommand);
	request_packet.command=afpGetIcon;
	request_packet.pad1=0;  
	/* I'm not entirely sure these two should be translated */
	request_packet.dtrefnum=htons(volume->dtrefnum);
	request_packet.filecreator=htonl(filecreator);
	request_packet.filetype=htonl(filetype);
	request_packet.icontype=icontype;
	request_packet.pad2=0;  
	request_packet.length=htons(length);

	return dsi_send(volume->server, (char *)&request_packet,
		sizeof(request_packet),1,afpGetIcon,icon);
}

int afp_geticon_reply(struct afp_server *server, char * buf, unsigned int size, void * other)
{
	struct {
		struct dsi_header header __attribute__((__packed__));
	} * reply_packet = (void *) buf;
	struct afp_icon * icon =other;
	unsigned int len=size-sizeof(*reply_packet);
	
	if (size < (sizeof (*reply_packet)+icon->maxsize)) {
		LOG(AFPFSD,LOG_WARNING,"getcomment icon is too short\n");
		return -1;
	}

	icon->size=len;
	memcpy(icon->data,buf+sizeof(*reply_packet),len);
	return 0;
}


int afp_addcomment(struct afp_volume *volume, unsigned int did, 
	char * pathname, char * comment, uint64_t *size)
{
	struct {
		struct dsi_header dsi_header __attribute__((__packed__));
		uint8_t command;
		uint8_t pad;
		uint16_t dtrefnum ;
		uint32_t dirid ;
	} __attribute__((__packed__)) * request_packet;
	unsigned int len=sizeof(*request_packet) + 
		sizeof_path_header(volume->server)+strlen(pathname) 
		+ strlen(comment)+1;
	char * msg, *p;
	int rc;

	msg=malloc(len+1);
	bzero(msg,len+1);
	p=msg+(sizeof(*request_packet));
	request_packet=(void *) msg;
	dsi_setup_header(volume->server,&request_packet->dsi_header,DSI_DSICommand);
	request_packet->command=afpAddComment;
	request_packet->pad=0;  
	request_packet->dtrefnum=htons(volume->dtrefnum);
	request_packet->dirid=htonl(did);
	copy_path(volume->server,p,pathname,strlen(pathname));
	unixpath_to_afppath(volume->server,p);

	p=msg+sizeof(*request_packet) +sizeof_path_header(volume->server)+strlen(pathname);

        if (((uint64_t) p) & 0x1) {
		/* Make sure we're on an even boundary */
		p++;  
		len++;
	}

	copy_to_pascal(p,comment);

	*size=strlen(comment);

	rc=dsi_send(volume->server, (char *)msg,len,1,afpAddComment,comment);
	free(msg);
	return rc;

}

int afp_getcomment(struct afp_volume *volume, unsigned int did, 
	char * pathname, struct afp_comment * comment)
{
	struct {
		struct dsi_header dsi_header __attribute__((__packed__));
		uint8_t command;
		uint8_t pad;
		uint16_t dtrefnum ; 
		uint32_t dirid ;
	} __attribute__((__packed__)) * request_packet;
	unsigned int len=sizeof(*request_packet) + 
		sizeof_path_header(volume->server)+strlen(pathname);
	char * msg, *path;
	int rc;

	msg=malloc(len);
	path=msg+(sizeof(*request_packet));
	request_packet=(void *) msg;
	dsi_setup_header(volume->server,&request_packet->dsi_header,DSI_DSICommand);
	request_packet->command=afpGetComment;
	request_packet->pad=0;  
	request_packet->dtrefnum=htons(volume->dtrefnum);
	request_packet->dirid=htonl(did);
	copy_path(volume->server,path,pathname,strlen(pathname));
	unixpath_to_afppath(volume->server,path);

	rc=dsi_send(volume->server, (char *)msg,len,1,afpGetComment,comment);
	free(msg);
	return rc;
}

int afp_getcomment_reply(struct afp_server *server, char * buf, unsigned int size, void * other)
{
	struct {
		struct dsi_header header __attribute__((__packed__));
		uint8_t commentlen;
	} __attribute__((__packed__)) * reply_packet = (void *) buf;
	struct afp_comment * comment=other;
	unsigned int len;
	
	if (size < sizeof (*reply_packet)) {
		LOG(AFPFSD,LOG_WARNING,"getcomment response is too short\n");
		return -1;
	}

	len=min(size-sizeof(*reply_packet),comment->maxsize);
	len=min(len,reply_packet->commentlen);
	memcpy(comment->data,buf+sizeof(*reply_packet),len);
	comment->size=len;
	return 0;
}

int afp_opendt(struct afp_volume *volume, unsigned short * refnum) 
{
	struct {
		struct dsi_header dsi_header __attribute__((__packed__));
		uint8_t command;
		uint8_t pad;
		uint16_t volid ;
	} __attribute__((__packed__)) request_packet;

	dsi_setup_header(volume->server,&request_packet.dsi_header,DSI_DSICommand);
	request_packet.command=afpOpenDT;
	request_packet.pad=0;  
	request_packet.volid=htons(volume->volid);

	return dsi_send(volume->server, (char *) &request_packet,sizeof(request_packet),1,afpOpenDT,refnum);
}


int afp_opendt_reply(struct afp_server *server, char * buf, unsigned int size, void * other)
{
	struct {
		struct dsi_header header __attribute__((__packed__));
		uint16_t refnum ;
	} __attribute__((__packed__)) * reply_packet = (void *) buf;
	unsigned short * refnum = other;
	
	if (size < sizeof (*reply_packet)) {
		LOG(AFPFSD,LOG_WARNING,"opendt response is too short\n");
		return -1;
	}
	*refnum=ntohs(reply_packet->refnum);

	return 0;
}

