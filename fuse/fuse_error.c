#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "libafpclient.h"
#include "fuse_internal.h"

/* Simple global capture state (not thread-safe, but adequate for mount startup) */
static int captured_fd = -1;
static int captured_stderr_fd = -1;  /* FD for captured stderr temp file */
static FILE *captured_stream = NULL;
static fpos_t pos;

void report_fuse_errors(struct fuse_client * c)
{
    char buf[MAX_ERROR_LEN];
    int len;

    if (captured_stderr_fd < 0) {
        return;  /* No capture was started */
    }

    fflush(stderr);

    if (captured_stream) {
        fclose(captured_stream);
        captured_stream = NULL;
    }

    dup2(captured_fd, fileno(stderr));
    close(captured_fd);
    clearerr(stderr);
    fsetpos(stderr, &pos);        /* for C9X */

    /* Rewind the temp file and read captured output */
    if (lseek(captured_stderr_fd, 0, SEEK_SET) < 0) {
        close(captured_stderr_fd);
        captured_stderr_fd = -1;
        return;
    }

    memset(buf, 0, MAX_ERROR_LEN);
    len = read(captured_stderr_fd, buf, MAX_ERROR_LEN);
    close(captured_stderr_fd);
    captured_stderr_fd = -1;

    if (len > 0) {
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "FUSE reported the following error:\n%s", buf);
    }
}

void fuse_capture_stderr_start(void)
{
    int fd;
    char tmpl[] = "/tmp/fuse_stderr_XXXXXX";
    fd = mkstemp(tmpl);

    if (fd < 0) {
        captured_stderr_fd = -1;
        return;
    }

    captured_stderr_fd = fd;
    fflush(stderr);
    fgetpos(stderr, &pos);
    captured_fd = dup(fileno(stderr));

    if (captured_fd >= 0) {
        FILE *f = fdopen(fd, "w+");

        if (f) {
            captured_stream = f;
            dup2(fileno(f), fileno(stderr));
        } else {
            close(fd);
            captured_stderr_fd = -1;
        }
    } else {
        close(fd);
        captured_stderr_fd = -1;
    }
}
