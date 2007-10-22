#include <afp.h>
#include <libafpclient.h>


struct libafpclient * libafpclient = NULL;


void client_setup(struct libafpclient * tmpclient)
{
	libafpclient=tmpclient;
}

