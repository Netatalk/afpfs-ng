
bin_PROGRAMS = afp

afp_SOURCES = client_interactive.c
afp_LDADD = -lreadline -lncurses  $(top_builddir)/lib/libafpclient.la
afp_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@ 

