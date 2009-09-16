INCLUDES = -I$(top_builddir)/bindings/c

bin_PROGRAMS = zmq_forwarder

zmq_forwarder_LDADD = $(top_builddir)/src/libzmq.la
zmq_forwarder_SOURCES = zmq_forwarder.cpp
zmq_forwarder_CXXFLAGS = -Wall -pedantic -Werror


