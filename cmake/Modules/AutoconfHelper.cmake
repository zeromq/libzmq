# Helper functions for translating autoconf projects. Several functions
# are lifted from the Mono sources

include (CheckCSourceCompiles)
include (CheckIncludeFile)
include (TestBigEndian)
include (CheckFunctionExists)
include (CheckTypeSize)
include (CheckCSourceRuns)


# Function to get the version information from the configure.ac file in the
# current directory. Its argument is the name of the library as passed to
# AC_INIT. It will set the variables ${LIBNAME}_VERSION and ${LIBNAME}_SOVERSION
function (ac_get_version libname)
  string(TOUPPER "${libname}" libname_upper)
  
  # Read the relevant content from configure.ac
  file (STRINGS configure.ac tmp_configure_ac
    REGEX "${libname_upper}_[_A-Z]+=[ \\t]*[0-9]+")
  
  # Product version
  string (REGEX REPLACE ".+MAJOR[_A-Z]+=([0-9]+).+MINOR[_A-Z]+=([0-9]+).+MICRO[_A-Z]+=([0-9]+).*"
    "\\1.\\2.\\3" ${libname_upper}_VERSION "${tmp_configure_ac}")
    
  # Library version for libtool
  string (REGEX REPLACE ".+CURRENT=([0-9]+).+REVISION=([0-9]+).+AGE=([0-9]+).*"
    "\\1.\\2.\\3" ${libname_upper}_SOVERSION "${tmp_configure_ac}")
  
  # Checks if the string needs to be displayed
  set (${libname_upper}_DISPLAYSTR_AUX 
    "Found ${libname} version ${${libname_upper}_VERSION}, soversion ${${libname_upper}_SOVERSION} from configure.ac"
  )
  if ((NOT ${libname_upper}_DISPLAYSTR) OR (NOT ${libname_upper}_DISPLAYSTR STREQUAL ${libname_upper}_DISPLAYSTR_AUX))
    set (${libname_upper}_DISPLAYSTR ${${libname_upper}_DISPLAYSTR_AUX} 
      CACHE INTERNAL "Version string from ${libname}" FORCE)
    message (STATUS ${${libname_upper}_DISPLAYSTR})
  endif ()
  
  # Export the result to the caller
  set(${libname_upper}_VERSION "${${libname_upper}_VERSION}" PARENT_SCOPE)
  set(${libname_upper}_SOVERSION "${${libname_upper}_SOVERSION}" PARENT_SCOPE)
endfunction()


# Also from mono's source code
# Implementation of AC_CHECK_HEADERS
# In addition, it also records the list of variables in the variable 
# 'autoheader_vars', and for each variable, a documentation string in the
# variable ${var}_doc
function(ac_check_headers)
  foreach (header ${ARGV})
	string(TOUPPER ${header} header_var)
	string(REPLACE "." "_" header_var ${header_var})
	string(REPLACE "/" "_" header_var ${header_var})
	set(header_var "HAVE_${header_var}")
	check_include_file (${header} ${header_var})
	set("${header_var}_doc" "Define to 1 if you have the <${header}> header file." PARENT_SCOPE)
	if (${header_var})
	  set("${header_var}_defined" "1" PARENT_SCOPE)
	endif()
	set("${header_var}_val" "1" PARENT_SCOPE)
	set (autoheader_vars ${autoheader_vars} ${header_var})
  endforeach()
  set (autoheader_vars ${autoheader_vars} PARENT_SCOPE)
endfunction()

# Function taken from mono's source code
function (ac_check_funcs)
  foreach (func ${ARGV})
    string(TOUPPER ${func} var)
    set(var "HAVE_${var}")
    set(${var})
    check_function_exists (${func} ${var})
    set("${var}_doc" "Define to 1 if you have the '${func}' function." PARENT_SCOPE)
    if (${var})
      set("${var}_defined" "1" PARENT_SCOPE)
      set(${var} yes PARENT_SCOPE)
    endif()
    set("${var}_val" "1" PARENT_SCOPE)
    set (autoheader_vars ${autoheader_vars} ${var})
  endforeach()
  set (autoheader_vars ${autoheader_vars} PARENT_SCOPE)
endfunction()


# Specifically, this macro checks for stdlib.h', stdarg.h',
# string.h', and float.h'; if the system has those, it probably
# has the rest of the ANSI C header files.  This macro also checks
# whether string.h' declares memchr' (and thus presumably the
# other mem' functions), whether stdlib.h' declare free' (and
# thus presumably malloc' and other related functions), and whether
# the ctype.h' macros work on characters with the high bit set, as
# ANSI C requires.
function (ac_header_stdc)
  if (STDC_HEADERS)
    return()
  endif()
  message(STATUS "Looking for ANSI-C headers")
  set(code "
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>

int main(int argc, char **argv)
{
  void *ptr;
  free((void*)1);
  ptr = memchr((void*)1, 0, 0);

  return (int)ptr;
}
")
  # FIXME Check the ctype.h high bit
  CHECK_C_SOURCE_COMPILES("${code}" STDC_HEADERS)
  if (STDC_HEADERS)
    set(STDC_HEADERS 1 PARENT_SCOPE)
	message(STATUS "Looking for ANSI-C headers - found")
  else()
    message(STATUS "Looking for ANSI-C headers - not found")
  endif()
endfunction()


# Also from the mono sources, kind of implements AC_SYS_LARGEFILE
function (ac_sys_largefile)
  CHECK_C_SOURCE_RUNS("
#include <sys/types.h>
#define BIG_OFF_T (((off_t)1<<62)-1+((off_t)1<<62))
int main (int argc, char **argv) {
    int big_off_t=((BIG_OFF_T%2147483629==721) &&
                   (BIG_OFF_T%2147483647==1));
    return big_off ? 0 : 1;
}
" HAVE_LARGE_FILE_SUPPORT)

# Check if it makes sense to define _LARGE_FILES or _FILE_OFFSET_BITS
  if (HAVE_LARGE_FILE_SUPPORT)
    return()
  endif()
  
  set (_LARGE_FILE_EXTRA_SRC "
#include <sys/types.h>
int main (int argc, char **argv) {
  return sizeof(off_t) == 8 ? 0 : 1;
}
")
  CHECK_C_SOURCE_RUNS ("#define _LARGE_FILES\n${_LARGE_FILE_EXTRA_SRC}" 
    HAVE_USEFUL_D_LARGE_FILES)
  if (NOT HAVE_USEFUL_D_LARGE_FILES)
    if (NOT DEFINED HAVE_USEFUL_D_FILE_OFFSET_BITS)
      set (SHOW_LARGE_FILE_WARNING TRUE)
    endif ()
    CHECK_C_SOURCE_RUNS ("#define _FILE_OFFSET_BITS 64\n${_LARGE_FILE_EXTRA_SRC}"
      HAVE_USEFUL_D_FILE_OFFSET_BITS)
	  if (HAVE_USEFUL_D_FILE_OFFSET_BITS)
      set (_FILE_OFFSET_BITS 64 PARENT_SCOPE)
	  elseif (SHOW_LARGE_FILE_WARNING)
	    message (WARNING "No 64 bit file support through off_t available.")
	  endif ()
  else ()
    set (_LARGE_FILES 1 PARENT_SCOPE)
  endif ()
endfunction ()


# Quick way to set some basic variables
# FIXME add support for variable number of arguments: only package and version are mandatory
function (ac_init package version bug_report tarname)
  set(PACKAGE_NAME "\"${package}\"" PARENT_SCOPE)
  set(PACKAGE_VERSION "\"${version}\"" PARENT_SCOPE)
  set(VERSION "\"${version}\"" PARENT_SCOPE)
  set(PACKAGE_STRING "\"${package} ${version}\"" PARENT_SCOPE)
  
  if (bug_report)
    set(PACKAGE_BUGREPORT "\"${bug_report}\"" PARENT_SCOPE)
  endif()
  if (tarname)
    set(PACKAGE_TARNAME "\"${tarname}\"" PARENT_SCOPE)
    set(PACKAGE "\"${tarname}\"" PARENT_SCOPE)
    set(PACKAGE_UNQUOTED "${tarname}" PARENT_SCOPE)
  endif()
endfunction()


# Checks for the const keyword, defining "HAS_CONST_SUPPORT"
# If it does not have support, defines "const" to 0 in the parent scope
function (ac_c_const)
  CHECK_C_SOURCE_COMPILES(
    "int main(int argc, char **argv){const int r = 0;return r;}"
    HAS_CONST_SUPPORT)
  if (NOT HAS_CONST_SUPPORT)
    set(const 0 PARENT_SCOPE)
  endif()
endfunction()


# Inline keyword support. Defines "inline" in the parent scope to the
# compiler internal keyword for inline in C
# TODO write a better test!
function (ac_c_inline)
  if (MSVC)
    set (inline __inline)
  elseif(CMAKE_COMPILER_IS_GNUC)
    set (inline __inline__)
  endif()
  set(inline "${inline}" PARENT_SCOPE)
endfunction()


# Test if you can safely include both <sys/time.h> and <time.h>
function (ac_header_time)
  CHECK_C_SOURCE_COMPILES(
    "#include <sys/time.h>\n#include <time.h>\nint main(int argc, char **argv) { return 0; }" 
    TIME_WITH_SYS_TIME)
  set(TIME_WITH_SYS_TIME ${TIME_WITH_SYS_TIME} PARENT_SCOPE)
endfunction()


# Native cpu byte order: 1 if big-endian (Motorola) or 0 if little-endian
# (Intel), setting "WORDS_BIGENDIAN" to 1 if big endian
function (ac_c_bigendian)
  TEST_BIG_ENDIAN(HOST_BIGENDIAN)
  if (HOST_BIGENDIAN)
    set(WORDS_BIGENDIAN 1 PARENT_SCOPE)
  endif()
endfunction()


# Check for off_t, setting "off_t" in the parent scope
function(ac_type_off_t)
  CHECK_TYPE_SIZE("off_t" SIZEOF_OFF_T)
  if (NOT SIZEOF_OFF_T)
    set(off_t "long int")
  endif()
  set(off_t ${off_t} PARENT_SCOPE)
endfunction()


# Check for size_t, setting "size_t" in the parent scope
function(ac_type_size_t)
  CHECK_TYPE_SIZE("size_t" SIZEOF_SIZE_T)
  if (NOT SIZEOF_SIZE_T)
    set(size_t "unsigned int")
  endif()
  set(size_t ${size_t} PARENT_SCOPE)
endfunction()


# Define "TM_IN_SYS_TIME" to 1 if <sys/time.h> declares "struct tm"
function(ac_struct_tm)
  CHECK_C_SOURCE_COMPILES(
    "#include <sys/time.h>\nint main(int argc, char **argv) { struct tm x; return 0; }"
    TM_IN_SYS_TIME
  )
  if (TM_IN_SYS_TIME)
    set (TM_IN_SYS_TIME 1 PARENT_SCOPE)
  endif()
endfunction()


# Obtain size of an 'type' and define as SIZEOF_TYPE
function (ac_check_sizeof typename)
  string(TOUPPER "SIZEOF_${typename}" varname)
	string(REPLACE " " "_" varname "${varname}")
  string(REPLACE "*" "p" varname "${varname}")
  CHECK_TYPE_SIZE("${typename}" ${varname} BUILTIN_TYPES_ONLY)
  if(NOT ${varname})
    set(${varname} 0 PARENT_SCOPE)
  endif()
endfunction()


# Check if the type exists, defines HAVE_<type>
function (ac_check_type typename)
  string(TOUPPER "${typename}" varname)
	string(REPLACE " " "_" varname "${varname}")
  string(REPLACE "*" "p" varname "${varname}")
  CHECK_TYPE_SIZE("${typename}" ${varname})
  if (NOT "${varname}" STREQUAL "")
    set("HAVE_${varname}" 1 PARENT_SCOPE)
    set("${varname}" "${typename}" PARENT_SCOPE)
  else()
    set("${varname}" "unknown" PARENT_SCOPE)  
  endif()
endfunction()


# Verifies if each type on the list exists, using the given prelude
function (ac_check_types type_list prelude)
  foreach(typename ${type_list})
    string(TOUPPER "HAVE_${typename}" varname)
    string(REPLACE " " "_" varname "${varname}")
    string(REPLACE "*" "p" varname "${varname}")
    CHECK_C_SOURCE_COMPILES("${prelude}\n ${typename} foo;" ${varname})
  endforeach()
endfunction()
