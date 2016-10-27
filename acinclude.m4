dnl ##############################################################################
dnl # LIBZMQ_CONFIG_LIBTOOL                                                      #
dnl # Configure libtool. Requires AC_CANONICAL_HOST                              #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CONFIG_LIBTOOL],  [{
    AC_REQUIRE([AC_CANONICAL_HOST])

    # Libtool configuration for different targets
    case "${host_os}" in
        *mingw*|*cygwin*)
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
dnl # LIBZMQ_CHECK_LANG_ICC([action-if-found], [action-if-not-found])            #
dnl # Check if the current language is compiled using ICC                        #
dnl # Adapted from http://software.intel.com/en-us/forums/showthread.php?t=67984 #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_ICC],
          [AC_CACHE_CHECK([whether we are using Intel _AC_LANG compiler],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#ifndef __INTEL_COMPILER
       error if not ICC
#endif
]])],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler="yes" ; $1],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler="no" ; $2])
])])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_LANG_SUN_STUDIO([action-if-found], [action-if-not-found])     #
dnl # Check if the current language is compiled using Sun Studio                 #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_SUN_STUDIO],
          [AC_CACHE_CHECK([whether we are using Sun Studio _AC_LANG compiler],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#if !defined(__SUNPRO_CC) && !defined(__SUNPRO_C)
       error if not sun studio
#endif
]])],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler="yes" ; $1],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler="no" ; $2])
])])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_LANG_CLANG([action-if-found], [action-if-not-found])          #
dnl # Check if the current language is compiled using clang                      #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_CLANG],
          [AC_CACHE_CHECK([whether we are using clang _AC_LANG compiler],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#ifndef __clang__
       error if not clang
#endif
]])],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler="yes" ; $1],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler="no" ; $2])
])])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_LANG_GCC4([action-if-found], [action-if-not-found])           #
dnl # Check if the current language is compiled using clang                      #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_GCC4],
          [AC_CACHE_CHECK([whether we are using gcc >= 4 _AC_LANG compiler],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_gcc4_compiler],
          [_AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[#if (!defined __GNUC__ || __GNUC__ < 4)
       error if not gcc4 or higher
#endif
]])],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_gcc4_compiler="yes" ; $1],
          [libzmq_cv_[]_AC_LANG_ABBREV[]_gcc4_compiler="no" ; $2])
])])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_DOC_BUILD                                                     #
dnl # Check whether to build documentation and install man-pages                 #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_DOC_BUILD], [{

    # Man pages are built/installed if asciidoc and xmlto are present
    #   --with-docs=no overrides this
    AC_ARG_WITH([docs],
        AS_HELP_STRING([--without-docs],
            [Don't build and install man pages [default=build]]),
        [with_docs=$withval])
    AC_ARG_WITH([documentation], [AS_HELP_STRING([--without-documentation],
        [Don't build and install man pages [default=build] DEPRECATED: use --without-docs])])

    if test "x$with_documentation" = "xno"; then
        AC_MSG_WARN([--without-documentation is DEPRECATED and will be removed in the next release, use --without-docs])
    fi
    if test "x$with_docs" = "xno" || test "x$with_documentation" = "xno"; then
        libzmq_build_doc="no"
        libzmq_install_man="no"
    else
        # Determine whether or not documentation should be built and installed.
        libzmq_build_doc="yes"
        libzmq_install_man="yes"
        # Check for asciidoc and xmlto and don't build the docs if these are not installed.
        AC_CHECK_PROG(libzmq_have_asciidoc, asciidoc, yes, no)
        AC_CHECK_PROG(libzmq_have_xmlto, xmlto, yes, no)
        if test "x$libzmq_have_asciidoc" = "xno" -o "x$libzmq_have_xmlto" = "xno"; then
            libzmq_build_doc="no"
            # Tarballs built with 'make dist' ship with prebuilt documentation.
            if ! test -f doc/zmq.7; then
                libzmq_install_man="no"
                AC_MSG_WARN([You are building an unreleased version of 0MQ and asciidoc or xmlto are not installed.])
                AC_MSG_WARN([Documentation will not be built and manual pages will not be installed.])
            fi
        fi

        # Do not install man pages if on mingw
        if test "x$libzmq_on_mingw" = "xyes"; then
            libzmq_install_man="no"
        fi
    fi

    AC_MSG_CHECKING([whether to build documentation])
    AC_MSG_RESULT([$libzmq_build_doc])

    AC_MSG_CHECKING([whether to install manpages])
    AC_MSG_RESULT([$libzmq_install_man])

    AM_CONDITIONAL(BUILD_DOC, test "x$libzmq_build_doc" = "xyes")
    AM_CONDITIONAL(INSTALL_MAN, test "x$libzmq_install_man" = "xyes")
}])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_LANG_COMPILER([action-if-found], [action-if-not-found])       #
dnl # Check that compiler for the current language actually works                #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_COMPILER], [{
    # Test that compiler for the current language actually works
    AC_CACHE_CHECK([whether the _AC_LANG compiler works],
                   [libzmq_cv_[]_AC_LANG_ABBREV[]_compiler_works],
                   [AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])],
                   [libzmq_cv_[]_AC_LANG_ABBREV[]_compiler_works="yes" ; $1],
                   [libzmq_cv_[]_AC_LANG_ABBREV[]_compiler_works="no" ; $2])
                   ])

    if test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_compiler_works" != "xyes"; then
        AC_MSG_ERROR([Unable to find a working _AC_LANG compiler])
    fi
}])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_COMPILERS                                                     #
dnl # Check compiler characteristics. This is so that we can AC_REQUIRE checks   #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_COMPILERS], [{
    # For that the compiler works and try to come up with the type
    AC_LANG_PUSH([C])
    LIBZMQ_CHECK_LANG_COMPILER

    LIBZMQ_CHECK_LANG_ICC
    LIBZMQ_CHECK_LANG_SUN_STUDIO
    LIBZMQ_CHECK_LANG_CLANG
    LIBZMQ_CHECK_LANG_GCC4
    AC_LANG_POP([C])

    AC_LANG_PUSH(C++)
    LIBZMQ_CHECK_LANG_COMPILER

    LIBZMQ_CHECK_LANG_ICC
    LIBZMQ_CHECK_LANG_SUN_STUDIO
    LIBZMQ_CHECK_LANG_CLANG
    LIBZMQ_CHECK_LANG_GCC4
    AC_LANG_POP([C++])

    # Set GCC and GXX variables correctly
    if test "x$GCC" = "xyes"; then
        if test "xyes" = "x$libzmq_cv_c_intel_compiler"; then
            GCC="no"
        fi
    fi

    if test "x$GXX" = "xyes"; then
        if test "xyes" = "x$libzmq_cv_cxx_intel_compiler"; then
            GXX="no"
        fi
    fi
}])

dnl ############################################################################
dnl # LIBZMQ_CHECK_LANG_FLAG([flag], [action-if-found], [action-if-not-found]) #
dnl # Check if the compiler supports given flag. Works for C and C++           #
dnl # Sets libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_[FLAG]=yes/no           #
dnl ############################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_FLAG], [{

    AC_REQUIRE([AC_PROG_GREP])

    AC_MSG_CHECKING([whether _AC_LANG compiler supports $1])

    libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save=$ac_[]_AC_LANG_ABBREV[]_werror_flag
    ac_[]_AC_LANG_ABBREV[]_werror_flag="yes"

    case "x[]_AC_LANG_ABBREV" in
        xc)
            libzmq_cv_check_lang_flag_save_CFLAGS="$CFLAGS"
            CFLAGS="$CFLAGS $1"
        ;;
        xcxx)
            libzmq_cv_check_lang_flag_save_CPPFLAGS="$CPPFLAGS"
            CPPFLAGS="$CPPFLAGS $1"
        ;;
        *)
            AC_MSG_WARN([testing compiler characteristic on an unknown language])
        ;;
    esac

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
                      # This hack exist for ICC, which outputs unknown options as remarks
                      # Remarks are not turned into errors even with -Werror on
                      [if ($GREP 'ignoring unknown' conftest.err ||
                           $GREP 'not supported' conftest.err) >/dev/null 2>&1; then
                           eval AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)="no"
                       else
                           eval AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)="yes"
                       fi],
                      [eval AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)="no"])

    case "x[]_AC_LANG_ABBREV" in
        xc)
            CFLAGS="$libzmq_cv_check_lang_flag_save_CFLAGS"
        ;;
        xcxx)
            CPPFLAGS="$libzmq_cv_check_lang_flag_save_CPPFLAGS"
        ;;
        *)
            # nothing to restore
        ;;
    esac

    # Restore the werror flag
    ac_[]_AC_LANG_ABBREV[]_werror_flag=$libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save

    # Call the action as the flags are restored
    AS_IF([eval test x$]AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)[ = "xyes"],
          [AC_MSG_RESULT(yes) ; $2], [AC_MSG_RESULT(no) ; $3])

}])

dnl ####################################################################################
dnl # LIBZMQ_CHECK_LANG_FLAG_PREPEND([flag], [action-if-found], [action-if-not-found]) #
dnl # Check if the compiler supports given flag. Works for C and C++                   #
dnl # This macro prepends the flag to CFLAGS or CPPFLAGS accordingly                   #
dnl # Sets libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_[FLAG]=yes/no                   #
dnl ####################################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_FLAG_PREPEND], [{
    LIBZMQ_CHECK_LANG_FLAG([$1])
    case "x[]_AC_LANG_ABBREV" in
       xc)
            AS_IF([eval test x$]AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)[ = "xyes"],
                  [CFLAGS="$1 $CFLAGS"; $2], $3)
       ;;
       xcxx)
            AS_IF([eval test x$]AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_flag_$1)[ = "xyes"],
                  [CPPFLAGS="$1 $CPPFLAGS"; $2], $3)
       ;;
    esac
}])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_ENABLE_DEBUG([action-if-found], [action-if-not-found])        #
dnl # Check whether to enable debug build and set compiler flags accordingly     #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_ENABLE_DEBUG], [{

    # Require compiler specifics
    AC_REQUIRE([LIBZMQ_CHECK_COMPILERS])

    # This flag is checked also in
    AC_ARG_ENABLE([debug], [AS_HELP_STRING([--enable-debug],
        [enable debugging information [default=disabled]])])

    AC_MSG_CHECKING(whether to enable debugging information)

    if test "x$enable_debug" = "xyes"; then

        # GCC, clang and ICC
        if test "x$GCC" = "xyes" -o \
                "x$libzmq_cv_c_intel_compiler" = "xyes" -o \
                "x$libzmq_cv_c_clang_compiler" = "xyes"; then
            CFLAGS="-g -O0 "
        elif test "x$libzmq_cv_c_sun_studio_compiler" = "xyes"; then
            CFLAGS="-g0 "
        fi

        # GCC, clang and ICC
        if test "x$GXX" = "xyes" -o \
                "x$libzmq_cv_cxx_intel_compiler" = "xyes" -o \
                "x$libzmq_cv_cxx_clang_compiler" = "xyes"; then
            CPPFLAGS="-g -O0 "
            CXXFLAGS="-g -O0 "
        # Sun studio
        elif test "x$libzmq_cv_cxx_sun_studio_compiler" = "xyes"; then
            CPPFLAGS="-g0 "
            CXXFLAGS="-g0 "
        fi

        if test "x$ZMQ_ORIG_CFLAGS" != "xnone"; then
            CFLAGS="${CFLAGS} ${ZMQ_ORIG_CFLAGS}"
        fi
        if test "x$ZMQ_ORIG_CPPFLAGS" != "xnone"; then
            CPPFLAGS="${CPPFLAGS} ${ZMQ_ORIG_CPPFLAGS}"
        fi
        if test "x$ZMQ_ORIG_CXXFLAGS" != "xnone"; then
            CXXFLAGS="${CXXFLAGS} ${ZMQ_ORIG_CXXFLAGS}"
        fi
        AC_MSG_RESULT(yes)
    else
        AC_MSG_RESULT(no)
    fi
}])

dnl ##############################################################################
dnl # LIBZMQ_WITH_GCOV([action-if-found], [action-if-not-found])                 #
dnl # Check whether to build with code coverage                                  #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_WITH_GCOV], [{
    # Require compiler specifics
    AC_REQUIRE([LIBZMQ_CHECK_COMPILERS])

    AC_ARG_WITH(gcov, [AS_HELP_STRING([--with-gcov=yes/no],
                      [with GCC Code Coverage reporting.])],
                      [ZMQ_GCOV="$withval"])

    AC_MSG_CHECKING(whether to enable code coverage)

    if test "x$ZMQ_GCOV" = "xyes"; then

        if test "x$GXX" != "xyes"; then
            AC_MSG_ERROR([--with-gcov=yes works only with GCC])
        fi

        CFLAGS="-g -O0 -fprofile-arcs -ftest-coverage"
        if test "x${ZMQ_ORIG_CPPFLAGS}" != "xnone"; then
            CFLAGS="${CFLAGS} ${ZMQ_ORIG_CFLAGS}"
        fi

        CPPFLAGS="-g -O0 -fprofile-arcs -ftest-coverage"
        if test "x${ZMQ_ORIG_CPPFLAGS}" != "xnone"; then
            CPPFLAGS="${CPPFLAGS} ${ZMQ_ORIG_CPPFLAGS}"
        fi

        CXXFLAGS="-fprofile-arcs"
        if test "x${ZMQ_ORIG_CXXFLAGS}" != "xnone"; then
            CXXFLAGS="${CXXFLAGS} ${ZMQ_ORIG_CXXFLAGS}"
        fi

        LIBS="-lgcov ${LIBS}"
    fi

    AS_IF([test "x$ZMQ_GCOV" = "xyes"],
          [AC_MSG_RESULT(yes) ; $1], [AC_MSG_RESULT(no) ; $2])
}])

dnl ##############################################################################
dnl # LIBZMQ_CHECK_WITH_FLAG([flags], [macro])                                   #
dnl # Runs a normal autoconf check with compiler flags                           #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_CHECK_WITH_FLAG], [{
    libzmq_check_with_flag_save_CFLAGS="$CFLAGS"
    libzmq_check_with_flag_save_CPPFLAGS="$CPPFLAGS"

    CFLAGS="$CFLAGS $1"
    CPPFLAGS="$CPPFLAGS $1"

    # Execute the macro
    $2

    CFLAGS="$libzmq_check_with_flag_save_CFLAGS"
    CPPFLAGS="$libzmq_check_with_flag_save_CPPFLAGS"
}])

dnl ##############################################################################
dnl # LIBZMQ_LANG_WALL([action-if-found], [action-if-not-found])                 #
dnl # How to define -Wall for the current compiler                               #
dnl # Sets libzmq_cv_[]_AC_LANG_ABBREV[]__wall_flag variable to found style      #
dnl ##############################################################################
AC_DEFUN([LIBZMQ_LANG_WALL], [{

    AC_MSG_CHECKING([how to enable additional warnings for _AC_LANG compiler])

    libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag=""

    # C compilers
    case "x[]_AC_LANG_ABBREV" in
       xc)
            # GCC, clang and ICC
            if test "x$GCC" = "xyes" -o \
                    "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes" -o \
                    "x$libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="-Wall"
            # Sun studio
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="-v"
            fi
       ;;
       xcxx)
            # GCC, clang and ICC
            if test "x$GXX" = "xyes" -o \
                    "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes" -o \
                    "x$libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="-Wall"
            # Sun studio
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag="+w"
            fi
       ;;
       *)
       ;;
    esac

    # Call the action
    if test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag" != "x"; then
        AC_MSG_RESULT([$libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag])
        $1
    else
        AC_MSG_RESULT([not found])
        $2
    fi
}])

dnl ####################################################################
dnl # LIBZMQ_LANG_STRICT([action-if-found], [action-if-not-found])     #
dnl # Check how to turn on strict standards compliance                 #
dnl ####################################################################
AC_DEFUN([LIBZMQ_LANG_STRICT], [{
    AC_MSG_CHECKING([how to enable strict standards compliance in _AC_LANG compiler])

    libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag=""

    # C compilers
    case "x[]_AC_LANG_ABBREV" in
       xc)
            # GCC, clang and ICC
            if test "x$GCC" = "xyes" -o "x$libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-pedantic"
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-strict-ansi"
            # Sun studio
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-Xc"
            fi
       ;;
       xcxx)
            # GCC, clang and ICC
            if test "x$GXX" = "xyes" -o "x$libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-pedantic"
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-strict-ansi"
            # Sun studio
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag="-compat=5"
            fi
       ;;
       *)
       ;;
    esac

    # Call the action
    if test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag" != "x"; then
        AC_MSG_RESULT([$libzmq_cv_[]_AC_LANG_ABBREV[]_strict_flag])
        $1
    else
        AC_MSG_RESULT([not found])
        $2
    fi
}])

dnl ########################################################################
dnl # LIBZMQ_LANG_WERROR([action-if-found], [action-if-not-found])         #
dnl # Check how to turn warnings to errors                                 #
dnl ########################################################################
AC_DEFUN([LIBZMQ_LANG_WERROR], [{
    AC_MSG_CHECKING([how to turn warnings to errors in _AC_LANG compiler])

    libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag=""

    # C compilers
    case "x[]_AC_LANG_ABBREV" in
       xc)
            # GCC, clang and ICC
            if test "x$GCC" = "xyes" -o "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-Werror"
            # Sun studio
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-errwarn=%all"
            fi
       ;;
       xcxx)
            # GCC, clang and ICC
            if test "x$GXX" = "xyes" -o "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-Werror"
            # Sun studio
            elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
                libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag="-errwarn=%all"
            fi
       ;;
       *)
       ;;
    esac

    # Call the action
    if test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag" != "x"; then
        AC_MSG_RESULT([$libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag])
        $1
    else
        AC_MSG_RESULT([not found])
        $2
    fi
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_LANG_PRAGMA([pragma], [action-if-found], [action-if-not-found]) #
dnl # Check if the compiler supports given pragma                                  #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_PRAGMA], [{
    # Need to know how to enable all warnings
    LIBZMQ_LANG_WALL

    AC_MSG_CHECKING([whether _AC_LANG compiler supports pragma $1])

    # Save flags
    libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save=$ac_[]_AC_LANG_ABBREV[]_werror_flag
    ac_[]_AC_LANG_ABBREV[]_werror_flag="yes"

    if test "x[]_AC_LANG_ABBREV" = "xc"; then
        libzmq_cv_check_lang_pragma_save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag"
    elif test "x[]_AC_LANG_ABBREV" = "xcxx"; then
        libzmq_cv_check_lang_pragma_save_CPPFLAGS="$CPPFLAGS"
        CPPFLAGS="$CPPFLAGS $libzmq_cv_[]_AC_LANG_ABBREV[]_wall_flag"
    else
        AC_MSG_WARN([testing compiler characteristic on an unknown language])
    fi

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[#pragma $1]])],
                      [eval AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_pragma_$1)="yes" ; AC_MSG_RESULT(yes)],
                      [eval AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_pragma_$1)="no" ; AC_MSG_RESULT(no)])

    if test "x[]_AC_LANG_ABBREV" = "xc"; then
        CFLAGS="$libzmq_cv_check_lang_pragma_save_CFLAGS"
    elif test "x[]_AC_LANG_ABBREV" = "xcxx"; then
        CPPFLAGS="$libzmq_cv_check_lang_pragma_save_CPPFLAGS"
    fi

    ac_[]_AC_LANG_ABBREV[]_werror_flag=$libzmq_cv_[]_AC_LANG_ABBREV[]_werror_flag_save

    # Call the action as the flags are restored
    AS_IF([eval test x$]AS_TR_SH(libzmq_cv_[]_AC_LANG_ABBREV[]_supports_pragma_$1)[ = "xyes"],
          [$2], [$3])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_LANG_VISIBILITY([action-if-found], [action-if-not-found])       #
dnl # Check if the compiler supports dso visibility                                #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_LANG_VISIBILITY], [{

    libzmq_cv_[]_AC_LANG_ABBREV[]_visibility_flag=""

    if test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_intel_compiler" = "xyes" -o \
            "x$libzmq_cv_[]_AC_LANG_ABBREV[]_clang_compiler" = "xyes" -o \
            "x$libzmq_cv_[]_AC_LANG_ABBREV[]_gcc4_compiler" = "xyes"; then
        LIBZMQ_CHECK_LANG_FLAG([-fvisibility=hidden],
                               [libzmq_cv_[]_AC_LANG_ABBREV[]_visibility_flag="-fvisibility=hidden"])
    elif test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_sun_studio_compiler" = "xyes"; then
        LIBZMQ_CHECK_LANG_FLAG([-xldscope=hidden],
                               [libzmq_cv_[]_AC_LANG_ABBREV[]_visibility_flag="-xldscope=hidden"])
    fi

    AC_MSG_CHECKING(whether _AC_LANG compiler supports dso visibility)

    AS_IF([test "x$libzmq_cv_[]_AC_LANG_ABBREV[]_visibility_flag" != "x"],
          [AC_MSG_RESULT(yes) ; $1], [AC_MSG_RESULT(no) ; $2])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_SOCK_CLOEXEC([action-if-found], [action-if-not-found])          #
dnl # Check if SOCK_CLOEXEC is supported                                           #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_SOCK_CLOEXEC], [{
    AC_CACHE_CHECK([whether SOCK_CLOEXEC is supported], [libzmq_cv_sock_cloexec],
        [AC_TRY_RUN([/* SOCK_CLOEXEC test */
#include <sys/types.h>
#include <sys/socket.h>

int main (int argc, char *argv [])
{
    int s = socket (PF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    return (s == -1);
}
        ],
        [libzmq_cv_sock_cloexec="yes"],
        [libzmq_cv_sock_cloexec="no"],
        [libzmq_cv_sock_cloexec="not during cross-compile"]
        )]
    )
    AS_IF([test "x$libzmq_cv_sock_cloexec" = "xyes"], [$1], [$2])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_ATOMIC_INSTRINSICS([action-if-found], [action-if-not-found])    #
dnl # Check if compiler supoorts __atomic_Xxx intrinsics                           #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_ATOMIC_INTRINSICS], [{
    AC_MSG_CHECKING(whether compiler supports __atomic_Xxx intrinsics)
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([
/* atomic intrinsics test */
int v = 0;
int main (int, char **)
{
    int t = __atomic_add_fetch (&v, 1, __ATOMIC_ACQ_REL);
    return t;
}
    ])],
    [AC_MSG_RESULT(yes) ; libzmq_cv_has_atomic_instrisics="yes" ; $1],
    [AC_MSG_RESULT(no)  ; libzmq_cv_has_atomic_instrisics="no"  ; $2]
    )
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_SO_KEEPALIVE([action-if-found], [action-if-not-found])          #
dnl # Check if SO_KEEPALIVE is supported                                           #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_SO_KEEPALIVE], [{
    AC_CACHE_CHECK([whether SO_KEEPALIVE is supported], [libzmq_cv_so_keepalive],
        [AC_TRY_RUN([/* SO_KEEPALIVE test */
#include <sys/types.h>
#include <sys/socket.h>

int main (int argc, char *argv [])
{
    int s, rc, opt = 1;
    return (
        ((s = socket (PF_INET, SOCK_STREAM, 0)) == -1) ||
        ((rc = setsockopt (s, SOL_SOCKET, SO_KEEPALIVE, (char*) &opt, sizeof (int))) == -1)
    );
}
        ],
        [libzmq_cv_so_keepalive="yes"],
        [libzmq_cv_so_keepalive="no"],
        [libzmq_cv_so_keepalive="not during cross-compile"]
        )]
    )
    AS_IF([test "x$libzmq_cv_so_keepalive" = "xyes"], [$1], [$2])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_TCP_KEEPCNT([action-if-found], [action-if-not-found])           #
dnl # Check if TCP_KEEPCNT is supported                                            #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_TCP_KEEPCNT], [{
    AC_CACHE_CHECK([whether TCP_KEEPCNT is supported], [libzmq_cv_tcp_keepcnt],
        [AC_TRY_RUN([/* TCP_KEEPCNT test */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main (int argc, char *argv [])
{
    int s, rc, opt = 1;
    return (
        ((s = socket (PF_INET, SOCK_STREAM, 0)) == -1) ||
        ((rc = setsockopt (s, SOL_SOCKET, SO_KEEPALIVE, (char*) &opt, sizeof (int))) == -1) ||
        ((rc = setsockopt (s, IPPROTO_TCP, TCP_KEEPCNT, (char*) &opt, sizeof (int))) == -1)
    );
}
        ],
        [libzmq_cv_tcp_keepcnt="yes"],
        [libzmq_cv_tcp_keepcnt="no"],
        [libzmq_cv_tcp_keepcnt="not during cross-compile"]
        )]
    )
    AS_IF([test "x$libzmq_cv_tcp_keepcnt" = "xyes"], [$1], [$2])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_TCP_KEEPIDLE([action-if-found], [action-if-not-found])          #
dnl # Check if TCP_KEEPIDLE is supported                                           #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_TCP_KEEPIDLE], [{
    AC_CACHE_CHECK([whether TCP_KEEPIDLE is supported], [libzmq_cv_tcp_keepidle],
        [AC_TRY_RUN([/* TCP_KEEPIDLE test */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main (int argc, char *argv [])
{
    int s, rc, opt = 1;
    return (
        ((s = socket (PF_INET, SOCK_STREAM, 0)) == -1) ||
        ((rc = setsockopt (s, SOL_SOCKET, SO_KEEPALIVE, (char*) &opt, sizeof (int))) == -1) ||
        ((rc = setsockopt (s, IPPROTO_TCP, TCP_KEEPIDLE, (char*) &opt, sizeof (int))) == -1)
    );
}
        ],
        [libzmq_cv_tcp_keepidle="yes"],
        [libzmq_cv_tcp_keepidle="no"],
        [libzmq_cv_tcp_keepidle="not during cross-compile"]
        )]
    )
    AS_IF([test "x$libzmq_cv_tcp_keepidle" = "xyes"], [$1], [$2])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_TCP_KEEPINTVL([action-if-found], [action-if-not-found])          #
dnl # Check if TCP_KEEPINTVL is supported                                           #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_TCP_KEEPINTVL], [{
    AC_CACHE_CHECK([whether TCP_KEEPINTVL is supported], [libzmq_cv_tcp_keepintvl],
        [AC_TRY_RUN([/* TCP_KEEPINTVL test */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main (int argc, char *argv [])
{
    int s, rc, opt = 1;
    return (
        ((s = socket (PF_INET, SOCK_STREAM, 0)) == -1) ||
        ((rc = setsockopt (s, SOL_SOCKET, SO_KEEPALIVE, (char*) &opt, sizeof (int))) == -1) ||
        ((rc = setsockopt (s, IPPROTO_TCP, TCP_KEEPINTVL, (char*) &opt, sizeof (int))) == -1)
    );
}
        ],
        [libzmq_cv_tcp_keepintvl="yes"],
        [libzmq_cv_tcp_keepintvl="no"],
        [libzmq_cv_tcp_keepintvl="not during cross-compile"]
        )]
    )
    AS_IF([test "x$libzmq_cv_tcp_keepintvl" = "xyes"], [$1], [$2])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_TCP_KEEPALIVE([action-if-found], [action-if-not-found])         #
dnl # Check if TCP_KEEPALIVE is supported                                          #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_TCP_KEEPALIVE], [{
    AC_CACHE_CHECK([whether TCP_KEEPALIVE is supported], [libzmq_cv_tcp_keepalive],
        [AC_TRY_RUN([/* TCP_KEEPALIVE test */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main (int argc, char *argv [])
{
    int s, rc, opt = 1;
    return (
        ((s = socket (PF_INET, SOCK_STREAM, 0)) == -1) ||
        ((rc = setsockopt (s, SOL_SOCKET, SO_KEEPALIVE, (char*) &opt, sizeof (int))) == -1) ||
        ((rc = setsockopt (s, IPPROTO_TCP, TCP_KEEPALIVE, (char*) &opt, sizeof (int))) == -1)
    );
}
        ],
        [libzmq_cv_tcp_keepalive="yes"],
        [libzmq_cv_tcp_keepalive="no"],
        [libzmq_cv_tcp_keepalive="not during cross-compile"]
        )]
    )
    AS_IF([test "x$libzmq_cv_tcp_keepalive" = "xyes"], [$1], [$2])
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_POLLER_KQUEUE([action-if-found], [action-if-not-found])         #
dnl # Checks kqueue polling system                                                 #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_POLLER_KQUEUE], [{
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
        ],[[
struct kevent t_kev;
kqueue();
        ]])],
        [$1], [$2]
    )
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_POLLER_EPOLL_RUN([action-if-found], [action-if-not-found])      #
dnl # Checks epoll polling system can actually run #
dnl # For cross-compile, only requires that epoll can link #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_POLLER_EPOLL], [{
    AC_RUN_IFELSE([
        AC_LANG_PROGRAM([
#include <sys/epoll.h>
        ],[[
struct epoll_event t_ev;
int r;
r = epoll_create(10);
return(r < 0);
        ]])],
        [$1],[$2],[
            AC_LINK_IFELSE([
                AC_LANG_PROGRAM([
#include <sys/epoll.h>
                ],[[
struct epoll_event t_ev;
epoll_create(10);
                ]])],
                [$1], [$2]
            )
        ]
    )
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_POLLER_DEVPOLL([action-if-found], [action-if-not-found])        #
dnl # Checks devpoll polling system                                                #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_POLLER_DEVPOLL], [{
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([
#include <sys/devpoll.h>
        ],[[
struct pollfd t_devpoll;
int fd = open("/dev/poll", O_RDWR);
        ]])],
        [$1], [$2]
    )
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_POLLER_POLLSET([action-if-found], [action-if-not-found])        #
dnl # Checks pollset polling system                                                #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_POLLER_POLLSET], [{
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([
#include <sys/poll.h>
#include <sys/pollset.h>
        ],[[
pollset_t ps = pollset_create(-1);
        ]])],
        [$1], [$2]
    )
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_POLLER_POLL([action-if-found], [action-if-not-found])           #
dnl # Checks poll polling system                                                   #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_POLLER_POLL], [{
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([
#include <poll.h>
        ],[[
struct pollfd t_poll;
poll(&t_poll, 1, 1);
        ]])],
        [$1], [$2]
    )
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_POLLER_SELECT([action-if-found], [action-if-not-found])         #
dnl # Checks select polling system                                                 #
dnl ################################################################################
AC_DEFUN([LIBZMQ_CHECK_POLLER_SELECT], [{
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([
#ifdef ZMQ_HAVE_WINDOWS
#include "winsock2.h"
#elif defined ZMQ_HAVE_OPENVMS
#include <sys/types.h>
#include <sys/time.h>
#else
#include <sys/select.h>
#endif
        ],[[
fd_set t_rfds;
struct timeval tv;
FD_ZERO(&t_rfds);
FD_SET(0, &t_rfds);
tv.tv_sec = 5;
tv.tv_usec = 0;
select(1, &t_rfds, NULL, NULL, &tv);
        ]])],
        [$1],[$2]
    )
}])

dnl ################################################################################
dnl # LIBZMQ_CHECK_POLLER([action-if-found], [action-if-not-found])                #
dnl # Choose polling system                                                        #
dnl ################################################################################

AC_DEFUN([LIBZMQ_CHECK_POLLER], [{
    # Allow user to override poller autodetection
    AC_ARG_WITH([poller],
        [AS_HELP_STRING([--with-poller],
        [choose polling system manually. Valid values are 'kqueue', 'epoll', 'devpoll', 'pollset', 'poll', 'select', or 'auto'. [default=auto]])])

    if test "x$with_poller" == "x"; then
        pollers=auto
    else
        pollers=$with_poller
    fi
    if test "$pollers" == "auto"; then
        # We search for pollers in this order
        pollers="kqueue epoll devpoll pollset poll select"
    fi

    # try to find suitable polling system. the order of testing is:
    AC_MSG_NOTICE([Choosing polling system from '$pollers'...])
    poller_found=0
    for poller in $pollers; do
        case "$poller" in
            kqueue)
                LIBZMQ_CHECK_POLLER_KQUEUE([
                    AC_MSG_NOTICE([Using 'kqueue' polling system])
                    AC_DEFINE(ZMQ_USE_KQUEUE, 1, [Use 'kqueue' polling system])
                    poller_found=1
                ])
            ;;
            epoll)
                LIBZMQ_CHECK_POLLER_EPOLL([
                    AC_MSG_NOTICE([Using 'epoll' polling system])
                    AC_DEFINE(ZMQ_USE_EPOLL, 1, [Use 'epoll' polling system])
                    poller_found=1
                ])
            ;;
            devpoll)
                LIBZMQ_CHECK_POLLER_DEVPOLL([
                    AC_MSG_NOTICE([Using 'devpoll' polling system])
                    AC_DEFINE(ZMQ_USE_DEVPOLL, 1, [Use 'devpoll' polling system])
                    poller_found=1
                ])
            ;;
            pollset)
                LIBZMQ_CHECK_POLLER_POLLSET([
                    AC_MSG_NOTICE([Using 'pollset' polling system])
                    AC_DEFINE(ZMQ_USE_POLLSET, 1, [Use 'pollset' polling system])
                    poller_found=1
                ])
            ;;
            poll)
                LIBZMQ_CHECK_POLLER_POLL([
                    AC_MSG_NOTICE([Using 'poll' polling system])
                    AC_DEFINE(ZMQ_USE_POLL, 1, [Use 'poll' polling system])
                    poller_found=1
                ])
            ;;
            select)
                LIBZMQ_CHECK_POLLER_SELECT([
                    AC_MSG_NOTICE([Using 'select' polling system])
                    AC_DEFINE(ZMQ_USE_SELECT, 1, [Use 'select' polling system])
                    poller_found=1
                ])
            ;;
        esac
        test $poller_found -eq 1 && break
    done
    if test $poller_found -eq 0; then
        AC_MSG_ERROR([None of '$pollers' are valid pollers on this platform])
    fi
}])
