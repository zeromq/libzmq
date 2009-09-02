INCLUDES = -I$(top_builddir)/include

bin_PROGRAMS = local_lat remote_lat local_thr remote_thr

local_lat_LDADD = $(top_builddir)/src/libzmq.la -lstdc++
local_lat_SOURCES = local_lat.c
local_lat_CXXFLAGS = -Wall -pedantic -Werror

remote_lat_LDADD = $(top_builddir)/src/libzmq.la -lstdc++
remote_lat_SOURCES = remote_lat.c
remote_lat_CXXFLAGS = -Wall -pedantic -Werror

local_thr_LDADD = $(top_builddir)/src/libzmq.la -lstdc++
local_thr_SOURCES = local_thr.c
local_thr_CXXFLAGS = -Wall -pedantic -Werror

remote_thr_LDADD = $(top_builddir)/src/libzmq.la -lstdc++
remote_thr_SOURCES = remote_thr.c
remote_thr_CXXFLAGS = -Wall -pedantic -Werror

