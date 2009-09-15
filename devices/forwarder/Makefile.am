INCLUDES = -I$(top_builddir)/c -I$(top_builddir)/cpp

bin_PROGRAMS = forwarder

forwarder_LDADD = $(top_builddir)/src/libzmq.la
forwarder_SOURCES = forwarder.cpp
forwarder_CXXFLAGS = -Wall -pedantic -Werror


