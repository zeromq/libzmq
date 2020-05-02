include(FindPackageHandleStandardArgs)

if (NOT MSVC)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(NSS3 "nss>=3.19")
    find_package_handle_standard_args(NSS3 DEFAULT_MSG NSS3_LIBRARIES NSS3_CFLAGS)
endif()

