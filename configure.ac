AC_PREREQ(2.69)

AC_INIT([libcstor], 0.0.0)
AC_CONFIG_MACRO_DIRS([m4])
AM_MAINTAINER_MODE

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

CSTOR_AC_DEBUG
CSTOR_AC_CONFIG_ZFS

AC_CONFIG_FILES([
                 Makefile
                 src/Makefile
                 include/Makefile
                 include/sys/Makefile
])

AC_OUTPUT

