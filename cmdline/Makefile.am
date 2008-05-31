
bin_PROGRAMS = afpcmd afpgetstatus

afpgetstatus_SOURCES = getstatus.c
afpgetstatus_LDADD = $(top_builddir)/lib/libafpclient.la
afpgetstatus_CFLAGS = -I$(top_srcdir)/include @CFLAGS@ 
afpgetstatus_LDFLAGS = -Wl,--as-needed -Wl,--enable-new-dtag

afpcmd_SOURCES = cmdline_afp.c  cmdline_main.c cmdline_testafp.c
afpcmd_LDADD = -lreadline -lncurses  $(top_builddir)/lib/libafpclient.la
afpcmd_CFLAGS = -I$(top_srcdir)/include @CFLAGS@ 

install-data-hook:
	mkdir -p $(DESTDIR)/$(mandir)/man1
	cp afpcmd.1 $(DESTDIR)$(mandir)/man1
	cp afpgetstatus.1 $(DESTDIR)$(mandir)/man1

