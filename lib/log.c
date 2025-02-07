
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "libafpclient.h"

void log_for_client(void * priv,
	enum loglevels loglevel, int logtype, char *format, ...) {

	va_list ap;
	char new_message[MAX_ERROR_LEN];

	va_start(ap, format);
	vsnprintf(new_message,MAX_ERROR_LEN,format,ap);
	va_end(ap);

	libafpclient->log_for_client(priv,loglevel,logtype,new_message);
}
 
void stdout_log_for_client(
		__attribute__((unused)) void * priv,
        __attribute__((unused)) enum loglevels loglevel,
		__attribute__((unused)) int logtype,
		const char *message)
{
	printf("%s\n",message);
}

