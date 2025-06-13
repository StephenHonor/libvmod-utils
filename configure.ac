AC_PREREQ([2.68])
AC_INIT([libvmod-utils], [0.1], [], [vmod-utils])
AC_COPYRIGHT([Copyright (c) 2011 Varnish Software AS])
AC_CONFIG_MACRO_DIR([])
AC_CONFIG_SRCDIR(src/vmod_utils.vcc)
AC_CONFIG_HEADER([config.h])

AC_GNU_SOURCE

AM_INIT_AUTOMAKE([1.12 -Wall -Werror foreign parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_AR

LT_PREREQ([2.2.6])
LT_INIT([dlopen disable-static])

ax_enable_compile_warnings=error
AX_COMPILER_FLAGS_CFLAGS

AC_ARG_WITH([rst2man],
    [
        AS_HELP_STRING(
            [--with-rst2man=PATH],
            [Location of rst2man (auto)])
    ],
    [RST2MAN="$withval"],
    [AC_CHECK_PROGS(RST2MAN, [rst2man rst2man.py], [])])


m4_ifndef([VARNISH_PREREQ], AC_MSG_ERROR([Need varnish.m4 -- see README.rst]))

VARNISH_VMODS([utils])

VMOD_TESTS="$(cd $srcdir/src && echo tests/*.vtc)"
AC_SUBST(VMOD_TESTS)

PKG_CHECK_VAR([LIBVARNISHAPI_LIBDIR], [varnishapi], [libdir])
AC_SUBST([VARNISH_LIBRARY_PATH],
	[$LIBVARNISHAPI_LIBDIR:$LIBVARNISHAPI_LIBDIR/varnish])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
