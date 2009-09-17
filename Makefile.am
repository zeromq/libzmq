if BUILD_PERF
DIR_PERF = perf
endif

SUBDIRS = src $(DIR_PERF) devices bindings
DIST_SUBDIRS = src perf devices bindings

EXTRA_DIST =  $(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.bz2 \
$(top_srcdir)/foreign/xmlParser/xmlParser.cpp \
$(top_srcdir)/foreign/xmlParser/xmlParser.hpp

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@

