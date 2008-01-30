#include <afp.h>
#include <libafpclient.h>


struct libafpclient * libafpclient = NULL;


void libafpclient_register(struct libafpclient * tmpclient)
{
	libafpclient=tmpclient;
}

