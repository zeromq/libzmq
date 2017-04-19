# ZeroMQ cmake module
#
# The following import targets are created
#
# ::
#
#   libzmq-static
#   libzmq
#
# This module sets the following variables in your project::
#
#   ZeroMQ_FOUND - true if ZeroMQ found on the system
#   ZeroMQ_INCLUDE_DIR - the directory containing ZeroMQ headers
#   ZeroMQ_LIBRARY - 
#   ZeroMQ_STATIC_LIBRARY

@PACKAGE_INIT@

if(NOT TARGET libzmq AND NOT TARGET libzmq-static)
  include("${CMAKE_CURRENT_LIST_DIR}/@PROJECT_NAME@Targets.cmake")

  get_target_property(@PROJECT_NAME@_INCLUDE_DIR libzmq INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(@PROJECT_NAME@_LIBRARY libzmq LOCATION)
  get_target_property(@PROJECT_NAME@_STATIC_LIBRARY libzmq-static LOCATION)
endif()
