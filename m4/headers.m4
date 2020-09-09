AC_DEFUN([CSTOR_AC_CONFIG_ZFS], [
    AC_ARG_WITH([zfs-headers],
        AC_HELP_STRING([--with-zfs-headers=dir],
            [include zfs headers]),
            [zfssrc="$withval"])

    ZFS_SRC=-I${zfssrc}
    AC_MSG_CHECKING([zfs header file source])
    AC_MSG_RESULT([$ZFS_SRC])
    AC_SUBST(ZFS_SRC)
	AC_SUBST(zfssrc)
    AC_DEFINE_UNQUOTED([ZFS_SRC], [$ZFS_SRC], [zfs header file source])


    AC_ARG_WITH([spl-headers],
        AC_HELP_STRING([--with-spl-headers=dir],
            [include libspl headers]),
            [splsrc="$withval"])

    SPL_SRC=-I${splsrc}

    AC_MSG_CHECKING([spl header file source])
    AC_MSG_RESULT([$SPL_SRC])
    AC_SUBST(SPL_SRC)
    AC_DEFINE_UNQUOTED([SPL_SRC], [$SPL_SRC], [spl header file source])
])
