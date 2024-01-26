
bin_PROGRAMS = afpcmd afpgetstatus

afpgetstatus_SOURCES = getstatus.c
afpgetstatus_LDADD = $(top_builddir)/lib/libafpclient.la
afpgetstatus_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@ 

afpcmd_SOURCES = cmdline_afp.c  cmdline_main.c cmdline_testafp.c

afpcmd_LDADD = -lreadline -lncurses  $(top_builddir)/lib/libafpclient.la
afpcmd_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@ 

noinst_HEADERS = cmdline_afp.h cmdline_main.h cmdline_testafp.h

man_MANS = afpcmd.1 afpgetstatus.1
EXTRA_DIST = afpcmd.1 afpgetstatus.1
