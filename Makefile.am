if BUILD_RUBY
DIR_R = ruby
endif

if BUILD_PERF
DIR_PERF = perf
endif

SUBDIRS = src $(DIR_R) $(DIR_PERF) devices bindings
DIST_SUBDIRS = src ruby perf devices bindings

EXTRA_DIST =  $(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.bz2

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@
