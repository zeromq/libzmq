INCLUDES = -I$(top_builddir)/include
LDADD = $(top_builddir)/src/libzmq.la

noinst_PROGRAMS = simple test_pair test_reqrep

simple_SOURCES = simple.cpp
test_pair_SOURCES = test_pair.cpp testutil.hpp
test_reqrep_SOURCES = test_reqrep.cpp testutil.hpp

TESTS = $(noinst_PROGRAMS)
