

bin_PROGRAMS = afpfsd afp_client

afpfsd_SOURCES = users.c map.c commands.c volinfo.c desktop.c attr.c dsi.c afp.c utils.c server.c volume.c directory.c files.c replyblock.c fork.c login.c daemon.c fuse_int.c log.c uams.c resource.c uams_def.c did.c codepage.c unicode.c map_def.c
afp_client_SOURCES = client.c uams_def.c map_def.c

afpfsd_LDADD = -lncurses -lfuse -lpthread $(LIBGCRYPT_LIBS)
afpfsd_CFLAGS=-g -Wall -D_FILE_OFFSET_BITS=64 $(LIBGCRYPT_CFLAGS)
afp_client_CFLAGS=-g -Wall -D_FILE_OFFSET_BITS=64 

EXTRA_DIST = README.txt

install-exec-local:
	$(INSTALL) -m 755 afpfsd afp_client $(DESTDIR)/$(bindir)

