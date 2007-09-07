#ifndef _LOG_H_
#define _LOG_H_

#include <stdarg.h>
#include <libafpclient_internal.h>

#define MAXLOGSIZE 2048

#define LOG_METHOD_SYSLOG 1
#define LOG_METHOD_STDOUT 2

void set_log_method(int m);

void make_log_entry(enum loglevels loglevel, int logtype,
                    char *message, ...);

typedef void(*make_log_func)
       (enum loglevels loglevel, int logtype, char *message, ...);
make_log_func set_log_location(char *srcfilename, int srclinenumber);

#define LOG make_log_entry

#endif
