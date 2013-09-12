EXTRA_DIST = curve_keygen.c z85_codec.h

INCLUDES = -I$(top_builddir)/include \
           -I$(top_srcdir)/include
# INCLUDES = -I$(top_srcdir)/include

bin_PROGRAMS = curve_keygen

curve_keygen_LDADD = $(top_builddir)/src/libzmq.la
curve_keygen_SOURCES = curve_keygen.c

