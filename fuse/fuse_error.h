#ifndef __FUSE_ERROR_H_
#define __FUSE_ERROR_H_

#include "fuse_internal.h"

void report_fuse_errors(struct fuse_client * c);
void fuse_capture_stderr_start(void);
const char *fuse_result_to_string(int fuse_result);
const char *mount_errno_to_string(int err);

#endif

