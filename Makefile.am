ACLOCAL_AMFLAGS = -I config

SUBDIRS = src doc perf devices
DIST_SUBDIRS = src doc perf devices builds/msvc

EXTRA_DIST = \
$(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.gz \
$(top_srcdir)/foreign/xmlParser/xmlParser.cpp \
$(top_srcdir)/foreign/xmlParser/xmlParser.hpp

dist-hook:
		-cp $(top_srcdir)/builds/redhat/zeromq.spec $(distdir)/zeromq.spec
		-sed s/\@PACKAGE_VERSION\@/@PACKAGE_VERSION@/ -i $(distdir)/zeromq.spec
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@
distclean-local:
		-rm -rf $(top_srcdir)/foreign/openpgm/@pgm_basename@

