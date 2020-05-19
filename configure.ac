#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([killer], [1], [/dev/null])

AM_INIT_AUTOMAKE

## AC_CONFIG_SRCDIR([src/killer.c])
# AC_CONFIG_SRCDIR([config.h.in]) # configure needs to locate itself
AC_CONFIG_SRCDIR([src/killer.c]) # configure needs to locate itself
AC_CONFIG_HEADERS([config.h])


# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([pcap_lookupdev],[pcap])
AC_SEARCH_LIBS([g_io_channel_new_file],[glib-2.0 glib libglib])
PKG_CHECK_MODULES([GLIB], [glib-2.0 gobject-2.0]) ## Depends on pkg-config !!!!

# Checks for header files.
# AC_CHECK_HEADERS([glib.h])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h \
                  stdlib.h string.h \
                  sys/socket.h unistd.h \
                  pcap.h])
# AC_CHECK_HEADERS  is necessary for config.h to have all the needed macros
# to search for if the given headers are present in the build environment.
# TODO: put config.h into a global header with header ward

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strdup])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
                 

AC_OUTPUT
