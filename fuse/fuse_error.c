#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "libafpclient.h"
#include "fuse_internal.h"

#define TMP_FILE "/tmp/fuse_stderr"

static FILE* original_stderr = NULL;

void report_fuse_errors(struct fuse_client* c) 
{
	char buf[1024];
	int fd;
	int len;
	
	fflush(stderr);
	stderr = original_stderr;
	
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
	FILE* tmp_file;
	
	fflush(stderr);
	original_stderr = stderr;
	
	tmp_file = fopen(TMP_FILE, "a");
	if (tmp_file) {
		stderr = tmp_file;
	}
}
