#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([lib/afp.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lncurses':
AC_CHECK_LIB([ncurses], [main])
AC_CHECK_LIB([readline],[readline])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])

#AC_ARG_WITH([gmp], [   --with-gmp\[=DIR\]     enable GNU MP library], [GMPDIR="$withval"])
#AC_SUBST([GMPDIR])

AC_CHECK_LIB([gmp], [__gmpz_init])

AC_CHECK_LIB([gcrypt], [gcry_cipher_open])
AM_PATH_LIBGCRYPT

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h stddef.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h utime.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa memset select socket strchr strerror strstr strtol])

AC_ARG_ENABLE(fuse, [ --disable-fuse    build without fuse])

if test "x$enable_fuse" != "xno" ; then
	AM_CONDITIONAL(HAVE_FUSE, true)
	AC_DEFINE([HAVE_FUSE], [], [quux])
	old_cflags=$CFLAGS
	old_cppflags=$CPPFLAGS
	CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64"
	CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64"
	AC_CHECK_HEADERS(fuse.h)
	if test "x$ac_cv_header_fuse_h" != "xyes" ; then
		AC_MSG_ERROR([Need to have FUSE installed])
	fi
	CFLAGS=$old_cflags
	CPPFLAGS=$old_cppflags
	AC_CHECK_LIB([fuse], [fuse_main])
	LIBFUSE_LDFLAGS="-lfuse"
	AC_SUBST(LIBFUSE_LDFLAGS)
else
	AM_CONDITIONAL(HAVE_FUSE, false)
	AC_DEFINE([HAVE_FUSE], [0], [Fuse disabled])
fi

AC_DEFINE([HAVE_GNOMEVFS], [], [foo])
AM_CONDITIONAL(HAVE_GNOMEVFS, false)
AC_ARG_ENABLE(gnome-vfs, [ --disable-gnome-vfs    build without gnome vfs])
if test "x$enable-gnome-vfs" != "xno" ; then
	PKG_CHECK_MODULES(gnomevfs, gnome-vfs-module-2.0 glib-2.0 ,
		[AM_CONDITIONAL(HAVE_GNOMEVFS, true)
		AC_DEFINE(HAVE_GNOMEVFS, [] [Set if we are building gnome vfs])]
		msg_gnome_vfs=yes,
		[AM_CONDITIONAL(HAVE_GNOMEVFS,false)])

	AC_ARG_WITH(gnome-vfs-libs, [  --with-gnome-vfs-libs    Location of gnome-vfs libraries.], 
		with_gnome_vfs_libs="$withval",
		with_gnome_vfs_libs="/usr/lib"
	)
	AC_ARG_WITH(gnome-vfs-include, [  --with-gnome-vfs-include    Location of gnome-vfs include files.], 
		with_gnome_vfs_include="$withval",
		with_gnome_vfs_include="/usr/include/gnome-vfs-2.0"
	)
	GNOMEVFS_MODULE_CFLAGS="-I/usr/include/gnome-vfs-module-2.0"
	GLIB_CFLAGS="-I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include"
	GCONF_CFLAGS="-I/usr/include/gconf/2"
	GNOMEVFS_CFLAGS="-D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -I${with_gnome_vfs_include} -L${with_gnome_vfs_libs} ${GLIB_CFLAGS} ${GCONF_CFLAGS} ${GNOMEVFS_MODULE_CFLAGS}"
fi

AC_SUBST(GNOMEVFS_CFLAGS)


AC_CONFIG_FILES([Makefile lib/Makefile fuse/Makefile cmdline/Makefile gnome-vfs/Makefile docs/man/Makefile docs/man/man1/Makefile])

AC_OUTPUT


