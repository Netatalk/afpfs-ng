#ifndef __FUSE_ERROR_H_
#define __FUSE_ERROR_H_

void report_fuse_errors(char * buf, unsigned int * buflen);
void fuse_capture_stderr_start(void);

#endif

