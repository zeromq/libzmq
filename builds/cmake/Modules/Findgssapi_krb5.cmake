if (NOT MSVC)
find_package(PkgConfig REQUIRED) 
pkg_check_modules(PC_GSSAPI_KRB5 "libgssapi_krb5")
if (PC_GSSAPI_KRB5_FOUND)
  set(pkg_config_names_private "${pkg_config_names_private} libgssapi_krb5")
endif()
if (NOT PC_GSSAPI_KRB5_FOUND)
    pkg_check_modules(PC_GSSAPI_KRB5 "gssapi_krb5")
    if (PC_GSSAPI_KRB5_FOUND)
      set(pkg_config_names_private "${pkg_config_names_private} gssapi_krb5")
    endif()
endif (NOT PC_GSSAPI_KRB5_FOUND)
if (PC_GSSAPI_KRB5_FOUND)
  set(GSSAPI_KRB5_INCLUDE_HINTS ${PC_GSSAPI_KRB5_INCLUDE_DIRS} ${PC_GSSAPI_KRB5_INCLUDE_DIRS}/*)
  set(GSSAPI_KRB5_LIBRARY_HINTS ${PC_GSSAPI_KRB5_LIBRARY_DIRS} ${PC_GSSAPI_KRB5_LIBRARY_DIRS}/*)
else()
  set(pkg_config_libs_private "${pkg_config_libs_private} -lgssapi_krb5")
endif()
endif (NOT MSVC)

# some libraries install the headers is a subdirectory of the include dir
# returned by pkg-config, so use a wildcard match to improve chances of finding
# headers and libraries.
find_path(
    GSSAPI_KRB5_INCLUDE_DIRS
    NAMES gssapi/gssapi_krb5.h
    HINTS ${GSSAPI_KRB5_INCLUDE_HINTS}
)

set (GSSAPI_NAMES libgssapi_krb5 gssapi_krb5)
if (${CMAKE_SIZEOF_VOID_P} STREQUAL 8)
  set (GSSAPI_NAMES ${GSSAPI_NAMES} gssapi64)
elseif (${CMAKE_SIZEOF_VOID_P} STREQUAL 4)
  set (GSSAPI_NAMES ${GSSAPI_NAMES} gssapi32)
endif()

find_library(
    GSSAPI_KRB5_LIBRARIES
    NAMES ${GSSAPI_NAMES}
    HINTS ${GSSAPI_KRB5_LIBRARY_HINTS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(gssapi_krb5 DEFAULT_MSG GSSAPI_KRB5_LIBRARIES GSSAPI_KRB5_INCLUDE_DIRS)
mark_as_advanced(GSSAPI_KRB5_FOUND GSSAPI_KRB5_LIBRARIES GSSAPI_KRB5_INCLUDE_DIRS)
