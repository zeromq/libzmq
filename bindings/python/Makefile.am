INCLUDES = -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/libzmq \
-I$(top_builddir)/libzmq $(PYTHON_INCLUDES)

pyexec_LTLIBRARIES = libpyzmq.la
libpyzmq_la_SOURCES = pyzmq.cpp
libpyzmq_la_LIBADD = $(top_builddir)/src/libzmq.la
libpyzmq_la_LDFLAGS = -avoid-version
