ACLOCAL_AMFLAGS = -I config

if BUILD_PERF
DIR_PERF = perf
endif

SUBDIRS = src doc $(DIR_PERF) devices bindings
DIST_SUBDIRS = src doc perf devices bindings

EXTRA_DIST = \
$(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.bz2 \
$(top_srcdir)/foreign/xmlParser/xmlParser.cpp \
$(top_srcdir)/foreign/xmlParser/xmlParser.hpp

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@
distclean-local:
		-rm -rf $(top_srcdir)/foreign/openpgm/@pgm_basename@

