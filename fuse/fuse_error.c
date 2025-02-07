#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "libafpclient.h"
#include "fuse_internal.h"

#define TMP_FILE "/tmp/fuse_stderr"

static FILE* tmp_stream = NULL;

void report_fuse_errors(struct fuse_client* c) 
{
	char buf[1024];
	int fd;
	int len;
	
	fflush(stderr);
	freopen("/dev/stderr", "w", stderr);
	if (tmp_stream) {
		fclose(tmp_stream);
	}
	
	if ((fd = open(TMP_FILE, O_RDONLY)) < 0) {
		return;
	}
	
	memset(buf, 0, 1024);
	len = read(fd, buf, 1024);
	close(fd);
	unlink(TMP_FILE);
	
	if (len > 0) {
		log_for_client((void*)c, AFPFSD, LOG_ERR,
			"FUSE reported the following error:\n%s", buf);
	}
}

void fuse_capture_stderr_start(void)
{
	fflush(stderr);
	tmp_stream = freopen(TMP_FILE, "a", stderr);
}
