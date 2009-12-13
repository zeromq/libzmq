if BUILD_PERF
DIR_PERF = perf
endif

if INSTALL_MAN
DIR_MAN = man
endif

SUBDIRS = src $(DIR_MAN) $(DIR_PERF) devices bindings examples
DIST_SUBDIRS = src man perf devices bindings examples

EXTRA_DIST = \
$(top_srcdir)/foreign/openpgm/@pgm2_basename@.tar.bz2 \
$(top_srcdir)/foreign/openpgm/create_custom_gsi_1.patch \
$(top_srcdir)/foreign/xmlParser/xmlParser.cpp \
$(top_srcdir)/foreign/xmlParser/xmlParser.hpp

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm2_basename@
