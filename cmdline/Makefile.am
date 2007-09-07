
bin_PROGRAMS = afp

afp_SOURCES = client_interactive.c

afp_LDADD = -lreadline -lncurses  $(top_builddir)/lib/libafpclient.la
afp_LDFLAGS = -export-dynamic
afp_CFLAGS = -I$(top_srcdir)/include -g -Wall @CFLAGS@ 

