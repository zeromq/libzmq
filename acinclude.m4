dnl ##############################################################################
dnl # AC_CONFIG_LIBTOOL                                                          #
dnl # Configure libtool. $host_os needs to be set before calling this macro      #
dnl ##############################################################################
AC_DEFUN([AC_CONFIG_LIBTOOL],  [{

    if test "x${host_os}" = "x"; then
        AC_MSG_ERROR([AC@&t@_CANONICAL_HOST not called before calling AC@&t@_CONFIG_LIBTOOL])
    fi

    # Libtool configuration for different targets
    case "${host_os}" in
        *mingw32*|*cygwin*)
            # Disable static build by default
            AC_DISABLE_STATIC
        ;;
        *)
            # Everything else with static enabled
            AC_ENABLE_STATIC
        ;;
    esac

    AC_LIBTOOL_WIN32_DLL
    AC_PROG_LIBTOOL
}])


dnl ##############################################################################
dnl # AC_CHECK_LANG_ICC                                                          #
dnl # Check if the current language is compiled using ICC                        #
dnl # Adapted from http://software.intel.com/en-us/forums/showthread.php?t=67984 #
dnl ##############################################################################
AC_DEFUN([AC_CHECK_LANG_ICC],
          [AC_CACHE_CHECK([whether we are using Intel _AC_LANG compiler],
          [ac_cv_[]_AC_LANG_ABBREV[]_intel_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#ifndef __INTEL_COMPILER
       error if not ICC
#endif
]])],
          [is_icc=yes],
          [is_icc=no])
ac_cv_[]_AC_LANG_ABBREV[]_intel_compiler=$is_icc
])])

dnl ##############################################################################
dnl # AC_CHECK_LANG_SUN_STUDIO                                                   #
dnl # Check if the current language is compiled using Sun Studio                 #
dnl ##############################################################################
AC_DEFUN([AC_CHECK_LANG_SUN_STUDIO],
          [AC_CACHE_CHECK([whether we are using Sun Studio _AC_LANG compiler],
          [ac_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#if !defined(__SUNPRO_CC) && !defined(__SUNPRO_C)
       error if not sun studio
#endif
]])],
          [is_sun_studio=yes],
          [is_sun_studio=no])
ac_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler=$is_sun_studio
])])

dnl ##############################################################################
dnl # AC_CHECK_DOC_BUILD                                                         #
dnl # Check whether to build documentation and install man-pages                 #
dnl ##############################################################################
AC_DEFUN([AC_CHECK_DOC_BUILD], [{
    # Allow user to disable doc build
    AC_ARG_WITH([documentation], [AS_HELP_STRING([--without-documentation],
        [disable documentation build even if asciidoc and xmlto are present [default=no]])])

    if test "x$with_documentation" = "xno"; then
        build_doc="no"
        install_man="no"
    else
        # Determine whether or not documentation should be built and installed.
        build_doc="yes"
        install_man="yes"
        # Check for asciidoc and xmlto and don't build the docs if these are not installed.
        AC_CHECK_PROG(have_asciidoc, asciidoc, yes, no)
        AC_CHECK_PROG(have_xmlto, xmlto, yes, no)
        if test "x$have_asciidoc" = "xno" -o "x$have_xmlto" = "xno"; then
            build_doc="no"
            # Tarballs built with 'make dist' ship with prebuilt documentation.
            if ! test -f doc/zmq.7; then
                install_man="no"
                AC_MSG_WARN([You are building an unreleased version of 0MQ and asciidoc or xmlto are not installed.])
                AC_MSG_WARN([Documentation will not be built and manual pages will not be installed.])
            fi
        fi

        # Do not install man pages if on mingw
        if test "x$on_mingw32" = "xyes"; then
            install_man="no"
        fi
    fi

    AC_MSG_CHECKING([whether to build documentation])
    AC_MSG_RESULT([$build_doc])

    AC_MSG_CHECKING([whether to install manpages])
    AC_MSG_RESULT([$install_man])

    AM_CONDITIONAL(BUILD_DOC, test "x$build_doc" = "xyes")
    AM_CONDITIONAL(INSTALL_MAN, test "x$install_man" = "xyes")
}])
