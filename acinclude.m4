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
