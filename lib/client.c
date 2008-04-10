#include <string.h>
#include <afp.h>
#include <libafpclient.h>


struct libafpclient * libafpclient = NULL;

static struct libafpclient null_afpclient = {
	.unmount_volume = NULL,
	.log_for_client = stdout_log_for_client,
	.forced_ending_hook = NULL,
	.scan_extra_fds = NULL,
	.loop_started = NULL,
};


void libafpclient_register(struct libafpclient * tmpclient)
{
	if (tmpclient) 
		libafpclient=tmpclient;
	else 
		libafpclient=&null_afpclient;
}

int afp_default_connection_request(
	struct afp_connection_request * conn_req, 
	struct afp_url * url)
{
	memset(conn_req, 0,sizeof(struct afp_connection_request));

	conn_req->url=*url;
	conn_req->url.requested_version=31;
	conn_req->uam_mask=default_uams_mask();
	if (strlen(url->uamname)>0)
		if ((conn_req->uam_mask = find_uam_by_name(url->uamname))==0)
			return -1;
	return 0;
}

