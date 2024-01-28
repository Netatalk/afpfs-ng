#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([afpfs-ng],[0.8.2])
AM_INIT_AUTOMAKE([dist-xz no-dist-gzip])
AC_CONFIG_SRCDIR([lib/afp.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT
AM_PROG_CC_C_O

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h gcrypt.h limits.h netdb.h readline/readline.h stddef.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h utime.h iconv.h])

# Checks for libraries.
AC_CHECK_LIB([ncurses], [initscr], [], [
  AC_MSG_ERROR([ncurses is required but not found.])
])
AC_CHECK_LIB([readline],[readline], [], [
  AC_MSG_ERROR([readline is required but not found.])
])
AC_CHECK_LIB([pthread], [pthread_create], [], [
  AC_MSG_ERROR([pthread is required but not found.])
])

AC_SUBST([CYCLE_OBJ])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa memset select socket strchr strerror strstr strtol])

AM_CONDITIONAL(HAVE_LIBGCRYPT, false)

AC_ARG_ENABLE(gcrypt, [ --disable-gcrypt    build without gcrypt (limits supported UAMs)])
if test "x$enable_gcrypt" != "xno" ; then
	AC_CHECK_LIB([gcrypt], [gcry_cipher_open])
fi

AM_CONDITIONAL(HAVE_LIBFUSE, false)
AM_CONDITIONAL(HAVE_FUSE_H, false)

case $host in
	*-*-darwin*) 
	;;
	*) 
	AC_ARG_ENABLE(fuse, [ --disable-fuse    build without fuse])
	if test "x$enable_fuse" != "xno" ; then
		old_cflags=$CFLAGS
		old_cppflags=$CPPFLAGS
		CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=29 "
		CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64"
		AC_CHECK_HEADERS(fuse.h)
		if test "x$ac_cv_header_fuse_h" != "xyes" ; then
			AC_MSG_ERROR([FUSE is not installed.  To build without fuse, configure with '--disable-fuse'])
		fi
		AC_CHECK_LIB([fuse], [fuse_main])
		CFLAGS=$old_cflags
		CPPFLAGS=$old_cppflags
		LIBFUSE_LDFLAGS="-lfuse"
		AC_SUBST(LIBFUSE_LDFLAGS)
		AM_CONDITIONAL(HAVE_LIBFUSE, true)
	fi
	;;
esac

AC_CHECK_LIB([gmp], [__gmpz_init])




AC_CONFIG_FILES([lib/Makefile fuse/Makefile cmdline/Makefile Makefile include/Makefile docs/Makefile])

AC_OUTPUT


