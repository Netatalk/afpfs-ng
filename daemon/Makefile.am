bin_PROGRAMS = afpfsd afp_extra mount_afp

afp_extra_SOURCES = extra.c
afp_extra_CFLAGS = -I$(top_builddir)/include
afp_extra_LDADD = $(top_builddir)/lib/libafpclient.la $(top_builddir)/daemon/libafpsl.la


afpfsd_SOURCES = commands.c daemon.c fuse_int.c fuse_error.c daemon_client.c daemon_fuse.c
afpfsd_LDADD = $(top_builddir)/lib/libafpclient.la -lfuse
afpfsd_LDFLAGS = -export-dynamic -lfuse
afpfsd_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@

mount_afp_SOURCES = client.c
mount_afp_CFLAGS = -I$(top_srcdir)/include -D_FILE_OFFSET_BITS=64 @CFLAGS@
mount_afp_LDADD = $(top_builddir)/lib/libafpclient.la $(top_builddir)/daemon/libafpsl.la



lib_LTLIBRARIES = libafpsl.la
libafpsl_la_CFLAGS = -I$(top_srcdir)/include @CFLAGS@
libafpsl_la_SOURCES = stateless.c


install-data-hook:
	mkdir -p $(DESTDIR)/$(mandir)/man1
	cp afpfsd.1 $(DESTDIR)/$(mandir)/man1
	cp mount_afp.1 $(DESTDIR)/$(mandir)/man1
	cp afp_client.1 $(DESTDIR)/$(mandir)/man1

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/afp_client
	$(LN_S) mount_afp $(DESTDIR)$(bindir)/afp_client
	cp afpfs $(DESTDIR)$(bindir)/afpfs



