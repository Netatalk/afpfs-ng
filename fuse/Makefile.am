bin_PROGRAMS = afpfsd mount_afp

mount_afp_SOURCES = client.c
mount_afp_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@
mount_afp_LDADD = $(top_builddir)/lib/libafpclient.la

afpfsd_SOURCES = commands.c daemon.c fuse_int.c fuse_error.c
afpfsd_LDADD = $(top_builddir)/lib/libafpclient.la
afpfsd_LDFLAGS = -export-dynamic
afpfsd_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/afp_client
	$(LN_S) mount_afp $(DESTDIR)$(bindir)/afp_client
