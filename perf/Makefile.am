INCLUDES = -I$(top_builddir)/include

noinst_PROGRAMS = local_lat remote_lat local_thr remote_thr
EXTRA_DIST = helpers.h

local_lat_LDADD = $(top_builddir)/src/libzmq.la
local_lat_SOURCES = local_lat.cpp helpers.cpp

remote_lat_LDADD = $(top_builddir)/src/libzmq.la
remote_lat_SOURCES = remote_lat.cpp helpers.cpp

local_thr_LDADD = $(top_builddir)/src/libzmq.la
local_thr_SOURCES = local_thr.cpp helpers.cpp

remote_thr_LDADD = $(top_builddir)/src/libzmq.la
remote_thr_SOURCES = remote_thr.cpp helpers.cpp
