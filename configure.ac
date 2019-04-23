AC_PREREQ(2.69)

AC_INIT([libzrepl], 0.0.0, [user@xyz.com])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET

LT_INIT

AC_CANONICAL_HOST

# Checks for programs.

# Checks for libraries.

# Checks for header files.
AM_PROG_CC_C_O
AC_PROG_CC_C99
AC_CONFIG_HEADER(config.h)
AC_HEADER_STDC

#AC_CHECK_HEADERS(fcntl.h limits.h strings.h syslog.h unistd.h [sys/cdefs.h] [sys/param.h] stdarg.h locale.h xlocale.h endian.h)
#AC_CHECK_HEADER(inttypes.h,[AC_DEFINE([JSON_C_HAVE_INTTYPES_H],[1],[Public define for json_inttypes.h])])

AC_CONFIG_FILES([
                 Makefile
                 src/Makefile
])

AC_OUTPUT

