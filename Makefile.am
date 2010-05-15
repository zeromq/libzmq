ACLOCAL_AMFLAGS = -I config

SUBDIRS = src doc perf devices zmqd
DIST_SUBDIRS = src doc perf devices zmqd builds/msvc

EXTRA_DIST = \
$(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.gz \
$(top_srcdir)/foreign/xmlParser/xmlParser.cpp \
$(top_srcdir)/foreign/xmlParser/xmlParser.hpp

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@
distclean-local:
		-rm -rf $(top_srcdir)/foreign/openpgm/@pgm_basename@

