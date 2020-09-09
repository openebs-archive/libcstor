dnl # Check if gcc supports -Wframe-larger-than=<size> option.
AC_DEFUN([CSTOR_AC_CONFIG_USER_FRAME_LARGER_THAN], [
	AC_MSG_CHECKING([for -Wframe-larger-than=<size> support])

	AS_IF([echo "$CFLAGS" | grep O0 >/dev/null],
	[
		echo "disabled because -O0"
	],
	[
		saved_flags="$CFLAGS"
		CFLAGS="$CFLAGS -Wframe-larger-than=1024"

		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
		[
			FRAME_LARGER_THAN=-Wframe-larger-than=1024
			AC_MSG_RESULT([yes])
		],
		[
			FRAME_LARGER_THAN=
			AC_MSG_RESULT([no])
		])

		CFLAGS="$saved_flags"
		AC_SUBST([FRAME_LARGER_THAN])
	])
])
