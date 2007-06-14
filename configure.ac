#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([attr.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lfuse':
AC_CHECK_LIB([fuse], [main])
# FIXME: Replace `main' with a function in `-lncurses':
AC_CHECK_LIB([ncurses], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])

# Check for libgmp.
AC_ARG_WITH([libgmp-prefix],
[  --with-libgmp-prefix=DIR
                          prefix where GNU MP library is installed (optional)],
	[ if test -d "$withval/lib" ; then
		if test -n "${need_dash_r}" ; then
			LDFLAGS="-L${withval}/lib -R${withval}/lib ${LDFLAGS}"
		else
			LDFLAGS="-L${withval}/lib ${LDFLAGS}"
		fi
	  else
		if test -n "${need_dash_r}" ; then
			LDFLAGS="-L${withval} -R${withval} ${LDFLAGS}"
		else
			LDFLAGS="-L${withval} ${LDFLAGS}"
		fi
	  fi
	  if test -d "$withval/include" ; then
		CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
	  else
		CPPFLAGS="-I${withval} ${CPPFLAGS}"
	  fi ])
AC_CHECK_LIB([gmp], [__gmpz_init])

# Check for libgcrypt.
AM_PATH_LIBGCRYPT
AC_CHECK_LIB([gcrypt], [gcry_cipher_open])

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
