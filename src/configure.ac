#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([killer], [1], [/dev/null])
AC_CONFIG_SRCDIR([killer.c])
AC_CONFIG_HEADERS([config.h])


# From stackoverflow to make glib work
PKG_CHECK_MODULES(GLIB, glib-2.0 gobject-2.0)
#PKG_CHECK_MODULES([PCAP], [pcap]) # Doesn't work for some reason.
# maybe it really only uses pkg-config to find packages.
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)
AC_CHECK_LIB([pcap], [pcap_lookupdev])

# Checks for programs.
AM_INIT_AUTOMAKE
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])
#AC_CHECK_HEADER([glib.h],, [AC_MSG_ERROR([ERROR!: glib.h file NOT found.])])
#AC_CHECK_LIB([glib-2.0], [g_free])
#AC_CHECK_LIB([pcap], [pcap_lookupdev])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([strdup])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
