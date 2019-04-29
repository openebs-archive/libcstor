AC_DEFUN([CSTOR_AC_DEBUG], [
	AC_MSG_CHECKING([whether assertion support will be enabled])
	AC_ARG_ENABLE([debug],
		[AS_HELP_STRING([--enable-debug],
		[Enable assertion support @<:@default=no@:>@])],
		[],
		[enable_debug=no])

    AS_IF([test "x$enable_debug" == xyes], [
        DEBUG_FLAGS=-DDEBUG
    ],[
        DEBUG_FLAGS=-DNDEBUG
    ])

    CFLAGS="$CFLAGS $DEBUG_FLAGS"
	AC_MSG_RESULT([$enable_debug])
])
