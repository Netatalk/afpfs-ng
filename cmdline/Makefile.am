
bin_PROGRAMS = afpcmd

afpcmd_SOURCES = cmdline_afp.c  cmdline_main.c cmdline_testafp.c

afpcmd_LDADD = -lreadline -lncurses  $(top_builddir)/lib/libafpclient.la
afpcmd_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@ 

