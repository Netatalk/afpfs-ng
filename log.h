#ifndef _LOG_H_
#define _LOG_H_

#include <stdarg.h>

#define MAXLOGSIZE 2048

enum loglevels {
	AFPFSD,
};

#define LOG_METHOD_SYSLOG 0
#define LOG_METHOD_STDOUT 1

void set_log_method(int m);

void make_log_entry(enum loglevels loglevel, int logtype,
                    char *message, ...);

typedef void(*make_log_func)
       (enum loglevels loglevel, int logtype, char *message, ...);
make_log_func set_log_location(char *srcfilename, int srclinenumber);

#define LOG make_log_entry

#endif
