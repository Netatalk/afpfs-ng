#include "afp.h"
#include "libafpclient.h"

static struct libafpclient null_afpclient = {
    .unmount_volume = NULL,
    .log_for_client = stdout_log_for_client,
    .forced_ending_hook = NULL,
    .scan_extra_fds = NULL,
    .loop_started = NULL,
};

struct libafpclient *libafpclient = &null_afpclient;


void libafpclient_register(struct libafpclient * tmpclient)
{
    if (tmpclient) {
        libafpclient = tmpclient;
    } else {
        libafpclient = &null_afpclient;
    }
}

