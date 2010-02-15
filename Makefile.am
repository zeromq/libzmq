ACLOCAL_AMFLAGS = -I config

if BUILD_PERF
DIR_PERF = perf
endif

SUBDIRS = src doc $(DIR_PERF) devices bindings examples
DIST_SUBDIRS = src doc perf devices bindings examples

EXTRA_DIST = \
$(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.bz2 \
$(top_srcdir)/foreign/xmlParser/xmlParser.cpp \
$(top_srcdir)/foreign/xmlParser/xmlParser.hpp

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@
clean-local:
		-rm -rf $(top_srcdir)/foreign/openpgm/@pgm_basename@

