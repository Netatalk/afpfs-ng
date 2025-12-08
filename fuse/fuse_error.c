#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "libafpclient.h"
#include "fuse_internal.h"

/* Thread-local storage for stderr capture state */
struct stderr_capture_state {
    int captured_fd;
    fpos_t pos;
    char tmp_file[256];
};

static pthread_key_t stderr_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static void make_key(void)
{
    pthread_key_create(&stderr_key, free);
}

static struct stderr_capture_state *get_capture_state(void)
{
    pthread_once(&key_once, make_key);
    struct stderr_capture_state *state = pthread_getspecific(stderr_key);

    if (!state) {
        state = calloc(1, sizeof(struct stderr_capture_state));
        pthread_setspecific(stderr_key, state);
    }

    return state;
}

void report_fuse_errors(struct fuse_client * c)
{
    char buf[MAX_ERROR_LEN];
    int fd;
    int len;
    struct stderr_capture_state *state = get_capture_state();

    if (!state || state->tmp_file[0] == '\0') {
        return;  /* No capture was started */
    }

    fflush(stderr);
    dup2(state->captured_fd, fileno(stderr));
    close(state->captured_fd);
    clearerr(stderr);
    fsetpos(stderr, &state->pos);        /* for C9X */

    if ((fd = open(state->tmp_file, O_RDONLY)) < 0) {
        state->tmp_file[0] = '\0';  /* Mark as inactive */
        return;
    }

    memset(buf, 0, MAX_ERROR_LEN);
    len = read(fd, buf, MAX_ERROR_LEN);
    close(fd);
    unlink(state->tmp_file);
    state->tmp_file[0] = '\0';  /* Mark as inactive */

    if (len > 0)
        log_for_client((void *)c, AFPFSD, LOG_ERR,
                       "FUSE reported the following error:\n%s", buf);
}

void fuse_capture_stderr_start(void)
{
    struct stderr_capture_state *state = get_capture_state();
    /* Create unique temporary file for this thread */
    snprintf(state->tmp_file, sizeof(state->tmp_file),
             "/tmp/fuse_stderr_%lu_%ld",
             (unsigned long)pthread_self(), (long)getpid());
    fflush(stderr);
    fgetpos(stderr, &state->pos);
    state->captured_fd = dup(fileno(stderr));
    freopen(state->tmp_file, "w", stderr);
}
