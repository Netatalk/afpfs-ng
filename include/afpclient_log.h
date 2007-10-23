#ifndef _LOG_H_
#define _LOG_H_

#include <libafpclient.h>

#define MAXLOGSIZE 2048

#define LOG_METHOD_SYSLOG 1
#define LOG_METHOD_STDOUT 2

void set_log_method(int m);


void log_for_client(struct client * c,
        enum loglevels loglevel, int logtype, char * message, ...);


void make_log_entry(enum loglevels loglevel, int logtype,
                    char *message, ...);

typedef void(*make_log_func)
       (enum loglevels loglevel, int logtype, char *message, ...);
make_log_func set_log_location(char *srcfilename, int srclinenumber);

void stdout_log_for_client(struct client * c,
	enum loglevels loglevel, int logtype, char *message, ...);


#define LOG make_log_entry

#endif
