dnl ##############################################################################
dnl # AC_ZMQ_CONFIG_LIBTOOL                                                      #
dnl # Configure libtool. Requires AC_CANONICAL_HOST                              #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CONFIG_LIBTOOL],  [{
    AC_REQUIRE([AC_CANONICAL_HOST])

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
}])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_LANG_ICC([action-if-found], [action-if-not-found])            #
dnl # Check if the current language is compiled using ICC                        #
dnl # Adapted from http://software.intel.com/en-us/forums/showthread.php?t=67984 #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_LANG_ICC],
          [AC_CACHE_CHECK([whether we are using Intel _AC_LANG compiler],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#ifndef __INTEL_COMPILER
       error if not ICC
#endif
]])],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler="yes" ; $1],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler="no" ; $2])
])])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_LANG_SUN_STUDIO([action-if-found], [action-if-not-found])     #
dnl # Check if the current language is compiled using Sun Studio                 #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_LANG_SUN_STUDIO],
          [AC_CACHE_CHECK([whether we are using Sun Studio _AC_LANG compiler],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#if !defined(__SUNPRO_CC) && !defined(__SUNPRO_C)
       error if not sun studio
#endif
]])],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler="yes" ; $1],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler="no" ; $2])
])])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_LANG_CLANG([action-if-found], [action-if-not-found])          #
dnl # Check if the current language is compiled using clang                      #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_LANG_CLANG],
          [AC_CACHE_CHECK([whether we are using clang _AC_LANG compiler],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#ifndef __clang__
       error if not clang
#endif
]])],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler="yes" ; $1],
          [ac_zmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler="no" ; $2])
])])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_DOC_BUILD                                                     #
dnl # Check whether to build documentation and install man-pages                 #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_DOC_BUILD], [{
    # Allow user to disable doc build
    AC_ARG_WITH([documentation], [AS_HELP_STRING([--without-documentation],
        [disable documentation build even if asciidoc and xmlto are present [default=no]])])

    if test "x$with_documentation" = "xno"; then
        ac_zmq_build_doc="no"
        ac_zmq_install_man="no"
    else
        # Determine whether or not documentation should be built and installed.
        ac_zmq_build_doc="yes"
        ac_zmq_install_man="yes"
        # Check for asciidoc and xmlto and don't build the docs if these are not installed.
        AC_CHECK_PROG(ac_zmq_have_asciidoc, asciidoc, yes, no)
        AC_CHECK_PROG(ac_zmq_have_xmlto, xmlto, yes, no)
        if test "x$ac_zmq_have_asciidoc" = "xno" -o "x$ac_zmq_have_xmlto" = "xno"; then
            ac_zmq_build_doc="no"
            # Tarballs built with 'make dist' ship with prebuilt documentation.
            if ! test -f doc/zmq.7; then
                ac_zmq_install_man="no"
                AC_MSG_WARN([You are building an unreleased version of 0MQ and asciidoc or xmlto are not installed.])
                AC_MSG_WARN([Documentation will not be built and manual pages will not be installed.])
            fi
        fi

        # Do not install man pages if on mingw
        if test "x$ac_zmq_on_mingw32" = "xyes"; then
            ac_zmq_install_man="no"
        fi
    fi

    AC_MSG_CHECKING([whether to build documentation])
    AC_MSG_RESULT([$ac_zmq_build_doc])

    AC_MSG_CHECKING([whether to install manpages])
    AC_MSG_RESULT([$ac_zmq_install_man])

    AM_CONDITIONAL(BUILD_DOC, test "x$ac_zmq_build_doc" = "xyes")
    AM_CONDITIONAL(INSTALL_MAN, test "x$ac_zmq_install_man" = "xyes")
}])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_LANG_COMPILER([action-if-found], [action-if-not-found])       #
dnl # Check that compiler for the current language actually works                #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_LANG_COMPILER], [{
    # Test that compiler for the current language actually works
    AC_CACHE_CHECK([whether the _AC_LANG compiler works],
                   [ac_zmq_cv_[]_AC_LANG_ABBREV[]_compiler_works],
                   [AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
                   [ac_zmq_cv_[]_AC_LANG_ABBREV[]_compiler_works="yes" ; $1],
                   [ac_zmq_cv_[]_AC_LANG_ABBREV[]_compiler_works="no" ; $2])
                   ])

    if test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_compiler_works" != "xyes"; then
        AC_MSG_ERROR([Unable to find a working _AC_LANG compiler])
    fi
}])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_COMPILERS                                                     #
dnl # Check compiler characteristics. This is so that we can AC_REQUIRE checks   #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_COMPILERS], [{
    # For that the compiler works and try to come up with the type
    AC_LANG_PUSH([C])
    AC_ZMQ_CHECK_LANG_COMPILER

    AC_ZMQ_CHECK_LANG_ICC
    AC_ZMQ_CHECK_LANG_SUN_STUDIO
    AC_ZMQ_CHECK_LANG_CLANG
    AC_LANG_POP([C])

    AC_LANG_PUSH(C++)
    AC_ZMQ_CHECK_LANG_COMPILER

    AC_ZMQ_CHECK_LANG_ICC
    AC_ZMQ_CHECK_LANG_SUN_STUDIO
    AC_ZMQ_CHECK_LANG_CLANG
    AC_LANG_POP([C++])

    # Set GCC and GXX variables correctly
    if test "x$GCC" = "xyes"; then
        if test "xyes" = "x$ac_zmq_cv_c_intel_compiler"; then
            GCC="no"
        fi
    fi

    if test "x$GXX" = "xyes"; then
        if test "xyes" = "x$ac_zmq_cv_cxx_intel_compiler"; then
            GXX="no"
        fi
    fi
}])

dnl ############################################################################
dnl # AC_ZMQ_CHECK_LANG_FLAG([flag], [action-if-found], [action-if-not-found]) #
dnl # Check if the compiler supports given flag. Works for C and C++           #
dnl # Sets ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_[FLAG]=yes/no           #
dnl ############################################################################
AC_DEFUN([AC_ZMQ_CHECK_LANG_FLAG], [{

    AC_MSG_CHECKING([whether _AC_LANG compiler supports $1])

    ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save=$ac_c_werror_flag
    ac_[]_AC_LANG_ABBREV[]_werror_flag="yes"

    case "x[]_AC_LANG_ABBREV" in
        xc)
            ac_zmq_cv_check_lang_flag_save_CFLAGS="$CFLAGS"
            CFLAGS="$CFLAGS $1"
        ;;
        xcxx)
            ac_zmq_cv_check_lang_flag_save_CPPFLAGS="$CPPFLAGS"
            CPPFLAGS="$CPPFLAGS $1"
        ;;
        *)
            AC_MSG_WARN([testing compiler characteristic on an unknown language])
        ;;
    esac

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
                      # This hack exist for ICC, which outputs unknown options as remarks
                      # Remarks are not turned into errors even with -Werror on
                      [if (grep 'ignoring unknown' conftest.err ||
                           grep 'not supported' conftest.err) >/dev/null 2>&1; then
                           eval AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)="no"
                       else
                           eval AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)="yes"
                       fi],
                      [eval AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)="no"])

    case "x[]_AC_LANG_ABBREV" in
        xc)
            CFLAGS="$ac_zmq_cv_check_lang_flag_save_CFLAGS"
        ;;
        xcxx)
            CPPFLAGS="$ac_zmq_cv_check_lang_flag_save_CPPFLAGS"
        ;;
        *)
            # nothing to restore
        ;;
    esac

    # Restore the werror flag
    ac_[]_AC_LANG_ABBREV[]_werror_flag=$ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save

    # Call the action as the flags are restored
    AS_IF([eval test x$]AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)[ = "xyes"],
          [AC_MSG_RESULT(yes) ; $2], [AC_MSG_RESULT(no) ; $3])

}])

dnl ####################################################################################
dnl # AC_ZMQ_CHECK_LANG_FLAG_PREPEND([flag], [action-if-found], [action-if-not-found]) #
dnl # Check if the compiler supports given flag. Works for C and C++                   #
dnl # This macro prepends the flag to CFLAGS or CPPFLAGS accordingly                   #
dnl # Sets ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_[FLAG]=yes/no                   #
dnl ####################################################################################
AC_DEFUN([AC_ZMQ_CHECK_LANG_FLAG_PREPEND], [{
    AC_ZMQ_CHECK_LANG_FLAG([$1])
    case "x[]_AC_LANG_ABBREV" in
       xc)
            AS_IF([eval test x$]AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)[ = "xyes"],
                  [CFLAGS="$1 $CFLAGS"; $2], $3)
       ;;
       xcxx)
            AS_IF([eval test x$]AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)[ = "xyes"],
                  [CPPFLAGS="$1 $CPPFLAGS"; $2], $3)
       ;;
    esac
}])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_ENABLE_DEBUG([action-if-found], [action-if-not-found])        #
dnl # Check whether to enable debug build and set compiler flags accordingly     #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_ENABLE_DEBUG], [{

    # Require compiler specifics
    AC_REQUIRE([AC_ZMQ_CHECK_COMPILERS])

    # This flag is checked also in
    AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug],
        [Enable debugging information [default=no]])])

    AC_MSG_CHECKING(whether to enable debugging information)

    if test "x$enable_debug" = "xyes"; then

        # GCC, clang and ICC
        if test "x$GCC" = "xyes" -o \
                "x$ac_zmq_cv_c_intel_compiler" = "xyes" -o \
                "x$ac_zmq_cv_c_clang_compiler" = "xyes"; then
            CFLAGS="-g -O0 "
        elif test "x$ac_zmq_cv_c_sun_studio_compiler" = "xyes"; then
            CFLAGS="-g0 "
        fi

        # GCC, clang and ICC
        if test "x$GXX" = "xyes" -o \
                "x$ac_zmq_cv_cxx_intel_compiler" = "xyes" -o \
                "x$ac_zmq_cv_cxx_clang_compiler" = "xyes"; then
            CPPFLAGS="-g -O0 "
            CXXFLAGS="-g -O0 "
        # Sun studio
        elif test "x$ac_zmq_cv_cxx_sun_studio_compiler" = "xyes"; then
            CPPFLAGS="-g0 "
            CXXFLAGS="-g0 "
        fi

        if test "x$LOCAL_CFLAGS" != "xnone"; then
            CFLAGS="${CFLAGS} ${LOCAL_CFLAGS}"
        fi
        if test "x$LOCAL_CPPFLAGS" != "xnone"; then
            CPPFLAGS="${CPPFLAGS} ${LOCAL_CPPFLAGS}"
        fi
        if test "x$LOCAL_CXXFLAGS" != "xnone"; then
            CXXFLAGS="${CXXFLAGS} ${LOCAL_CXXFLAGS}"
        fi
        AC_MSG_RESULT(yes)
    else
        AC_MSG_RESULT(no)
    fi
}])

dnl ##############################################################################
dnl # AC_ZMQ_CHECK_WITH_FLAG([flags], [macro])                                   #
dnl # Runs a normal autoconf check with compiler flags                           #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_CHECK_WITH_FLAG], [{
    ac_zmq_check_with_flag_save_CFLAGS="$CFLAGS"
    ac_zmq_check_with_flag_save_CPPFLAGS="$CPPFLAGS"

    CFLAGS="$CFLAGS $1"
    CPPFLAGS="$CPPFLAGS $1"

    # Execute the macro
    $2

    CFLAGS="$ac_zmq_check_with_flag_save_CFLAGS"
    CPPFLAGS="$ac_zmq_check_with_flag_save_CPPFLAGS"
}])

dnl ##############################################################################
dnl # AC_ZMQ_LANG_WALL([action-if-found], [action-if-not-found])                 #
dnl # How to define -Wall for the current compiler                               #
dnl # Sets ac_zmq_cv_[]_AC_LANG_ABBREV[]__wall_flag variable to found style      #
dnl ##############################################################################
AC_DEFUN([AC_ZMQ_LANG_WALL], [{

    AC_MSG_CHECKING([how to enable additional warnings for _AC_LANG compiler])

    ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag=""

    # C compilers
    case "x[]_AC_LANG_ABBREV" in
       xc)
            # GCC, clang and ICC
            if test "x$GCC" = "xyes" -o \
                    "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes" -o \
                    "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="-Wall"
            # Sun studio
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="-v"
            fi
       ;;
       xcxx)
            # GCC, clang and ICC
            if test "x$GXX" = "xyes" -o \
                    "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes" -o \
                    "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="-Wall"
            # Sun studio
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="+w"
            fi
       ;;
       *)
       ;;
    esac

    # Call the action
    if test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag" != "x"; then
        AC_MSG_RESULT([$ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag])
        $1
    else
        AC_MSG_RESULT([not found])
        $2
    fi
}])

dnl ####################################################################
dnl # AC_ZMQ_LANG_STRICT([action-if-found], [action-if-not-found])     #
dnl # Check how to turn on strict standards compliance                 #
dnl ####################################################################
AC_DEFUN([AC_ZMQ_LANG_STRICT], [{
    AC_MSG_CHECKING([how to enable strict standards compliance in _AC_LANG compiler])

    ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag=""

    # C compilers
    case "x[]_AC_LANG_ABBREV" in
       xc)
            # GCC, clang and ICC
            if test "x$GCC" = "xyes" -o "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-pedantic"
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-strict-ansi"
            # Sun studio
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-Xc"
            fi
       ;;
       xcxx)
            # GCC, clang and ICC
            if test "x$GXX" = "xyes" -o "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-pedantic"
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-strict-ansi"
            # Sun studio
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-compat=5"
            fi
       ;;
       *)
       ;;
    esac

    # Call the action
    if test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag" != "x"; then
        AC_MSG_RESULT([$ac_zmq_cv_[]_AC_LANG_ABBREV[]_strict_flag])
        $1
    else
        AC_MSG_RESULT([not found])
        $2
    fi
}])

dnl ########################################################################
dnl # AC_ZMQ_LANG_WERROR([action-if-found], [action-if-not-found])         #
dnl # Check how to turn warnings to errors                                 #
dnl ########################################################################
AC_DEFUN([AC_ZMQ_LANG_WERROR], [{
    AC_MSG_CHECKING([how to turn warnings to errors in _AC_LANG compiler])

    ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag=""

    # C compilers
    case "x[]_AC_LANG_ABBREV" in
       xc)
            # GCC, clang and ICC
            if test "x$GCC" = "xyes" -o "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-Werror"
            # Sun studio
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-errwarn=%all"
            fi
       ;;
       xcxx)
            # GCC, clang and ICC
            if test "x$GXX" = "xyes" -o "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-Werror"
            # Sun studio
            elif test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-errwarn=%all"
            fi
       ;;
       *)
       ;;
    esac

    # Call the action
    if test "x$ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag" != "x"; then
        AC_MSG_RESULT([$ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag])
        $1
    else
        AC_MSG_RESULT([not found])
        $2
    fi
}])

dnl ################################################################################
dnl # AC_ZMQ_CHECK_LANG_PRAGMA([pragma], [action-if-found], [action-if-not-found]) #
dnl # Check if the compiler supports given pragma                                  #
dnl ################################################################################
AC_DEFUN([AC_ZMQ_CHECK_LANG_PRAGMA], [{
    # Need to know how to enable all warnings
    AC_ZMQ_LANG_WALL

    AC_MSG_CHECKING([whether _AC_LANG compiler supports pragma $1])

    # Save flags
    ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save=$ac_[]_AC_LANG_ABBREV[]_werror_flag
    ac_[]_AC_LANG_ABBREV[]_werror_flag="yes"

    if test "x[]_AC_LANG_ABBREV" = "xc"; then
        ac_zmq_cv_check_lang_pragma_save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag"
    elif test "x[]_AC_LANG_ABBREV" = "xcxx"; then
        ac_zmq_cv_check_lang_pragma_save_CPPFLAGS="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS $ac_zmq_cv_[]_AC_LANG_ABBREV[]_wall_flag"
    else
        AC_MSG_WARN([testing compiler characteristic on an unknown language])
    fi

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[#pragma $1]])],
                      [eval AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_pragma_$1)="yes" ; AC_MSG_RESULT(yes)],
                      [eval AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_pragma_$1)="no" ; AC_MSG_RESULT(no)])

    if test "x[]_AC_LANG_ABBREV" = "xc"; then
        CFLAGS="$ac_zmq_cv_check_lang_pragma_save_CFLAGS"
    elif test "x[]_AC_LANG_ABBREV" = "xcxx"; then
        CPPFLAGS="$ac_zmq_cv_check_lang_pragma_save_CPPFLAGS"
    fi

    ac_[]_AC_LANG_ABBREV[]_werror_flag=$ac_zmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save

    # Call the action as the flags are restored
    AS_IF([eval test x$]AS_TR_SH(ac_zmq_cv_[]_AC_LANG_ABBREV[]_supports_pragma_$1)[ = "xyes"],
          [$2], [$3])
}])
