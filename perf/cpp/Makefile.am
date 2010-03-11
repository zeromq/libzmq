INCLUDES = -I$(top_srcdir)/include

noinst_PROGRAMS = local_lat remote_lat local_thr remote_thr

local_lat_LDADD = $(top_builddir)/src/libzmq.la
local_lat_SOURCES = local_lat.cpp
local_lat_CXXFLAGS = -Wall -pedantic -Werror

remote_lat_LDADD = $(top_builddir)/src/libzmq.la
remote_lat_SOURCES = remote_lat.cpp
remote_lat_CXXFLAGS = -Wall -pedantic -Werror

local_thr_LDADD = $(top_builddir)/src/libzmq.la
local_thr_SOURCES = local_thr.cpp
local_thr_CXXFLAGS = -Wall -pedantic -Werror

remote_thr_LDADD = $(top_builddir)/src/libzmq.la
remote_thr_SOURCES = remote_thr.cpp
remote_thr_CXXFLAGS = -Wall -pedantic -Werror

