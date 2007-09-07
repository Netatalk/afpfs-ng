bin_PROGRAMS = afpfsd afp_client

afp_client_SOURCES = client.c
afp_client_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@
afp_client_LDADD = $(top_builddir)/lib/libafpclient.la

afpfsd_SOURCES = commands.c daemon.c fuse_int.c
afpfsd_LDADD = $(top_builddir)/lib/libafpclient.la
afpfsd_LDFLAGS = -export-dynamic
afpfsd_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@
