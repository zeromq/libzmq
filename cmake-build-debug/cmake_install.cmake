# Install script for directory: /home/somdoron/git/libzmq

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "0")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib64/pkgconfig" TYPE FILE FILES "/home/somdoron/git/libzmq/cmake-build-debug/libzmq.pc")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so.5.2.2"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so.5"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      file(RPATH_CHECK
           FILE "${file}"
           RPATH "")
    endif()
  endforeach()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib64" TYPE SHARED_LIBRARY FILES
    "/home/somdoron/git/libzmq/cmake-build-debug/lib/libzmq.so.5.2.2"
    "/home/somdoron/git/libzmq/cmake-build-debug/lib/libzmq.so.5"
    )
  foreach(file
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so.5.2.2"
      "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so.5"
      )
    if(EXISTS "${file}" AND
       NOT IS_SYMLINK "${file}")
      if(CMAKE_INSTALL_DO_STRIP)
        execute_process(COMMAND "/usr/bin/strip" "${file}")
      endif()
    endif()
  endforeach()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib64" TYPE SHARED_LIBRARY FILES "/home/somdoron/git/libzmq/cmake-build-debug/lib/libzmq.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib64/libzmq.so")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/somdoron/git/libzmq/include/zmq.h"
    "/home/somdoron/git/libzmq/include/zmq_utils.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib64" TYPE STATIC_LIBRARY FILES "/home/somdoron/git/libzmq/cmake-build-debug/lib/libzmq.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/home/somdoron/git/libzmq/include/zmq.h"
    "/home/somdoron/git/libzmq/include/zmq_utils.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/zmq" TYPE FILE FILES "/home/somdoron/git/libzmq/cmake-build-debug/AUTHORS.txt")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/zmq" TYPE FILE FILES "/home/somdoron/git/libzmq/cmake-build-debug/COPYING.txt")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/zmq" TYPE FILE FILES "/home/somdoron/git/libzmq/cmake-build-debug/COPYING.LESSER.txt")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/zmq" TYPE FILE FILES "/home/somdoron/git/libzmq/cmake-build-debug/NEWS.txt")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xRefGuidex" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/doc/zmq" TYPE FILE FILES
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_atomic_counter_dec.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_atomic_counter_destroy.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_atomic_counter_inc.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_atomic_counter_new.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_atomic_counter_set.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_atomic_counter_value.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_bind.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_close.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_connect.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_ctx_destroy.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_ctx_get.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_ctx_new.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_ctx_set.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_ctx_shutdown.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_ctx_term.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_curve.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_curve_keypair.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_curve_public.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_disconnect.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_errno.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_getsockopt.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_gssapi.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_has.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_init.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_inproc.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_ipc.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_close.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_copy.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_data.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_get.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_gets.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_init.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_init_data.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_init_size.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_more.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_move.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_recv.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_routing_id.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_send.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_set.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_set_routing_id.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_msg_size.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_null.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_pgm.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_plain.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_poll.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_poller.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_proxy.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_proxy_steerable.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_recv.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_recvmsg.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_send.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_send_const.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_sendmsg.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_setsockopt.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_socket.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_socket_monitor.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_socket_monitor_versioned.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_strerror.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_tcp.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_term.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_timers.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_tipc.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_udp.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_unbind.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_version.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_vmci.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_z85_decode.html"
    "/home/somdoron/git/libzmq/cmake-build-debug/doc/zmq_z85_encode.html"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/ZeroMQ/ZeroMQTargets.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/ZeroMQ/ZeroMQTargets.cmake"
         "/home/somdoron/git/libzmq/cmake-build-debug/CMakeFiles/Export/share/cmake/ZeroMQ/ZeroMQTargets.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/ZeroMQ/ZeroMQTargets-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/ZeroMQ/ZeroMQTargets.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/ZeroMQ" TYPE FILE FILES "/home/somdoron/git/libzmq/cmake-build-debug/CMakeFiles/Export/share/cmake/ZeroMQ/ZeroMQTargets.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/ZeroMQ" TYPE FILE FILES "/home/somdoron/git/libzmq/cmake-build-debug/CMakeFiles/Export/share/cmake/ZeroMQ/ZeroMQTargets-debug.cmake")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/ZeroMQ" TYPE FILE FILES
    "/home/somdoron/git/libzmq/cmake-build-debug/ZeroMQConfig.cmake"
    "/home/somdoron/git/libzmq/cmake-build-debug/ZeroMQConfigVersion.cmake"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/somdoron/git/libzmq/cmake-build-debug/tests/cmake_install.cmake")
  include("/home/somdoron/git/libzmq/cmake-build-debug/unittests/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/somdoron/git/libzmq/cmake-build-debug/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
