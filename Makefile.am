if BUILD_PYTHON
DIR_P = python
endif

if BUILD_RUBY
DIR_R = ruby
endif

if BUILD_PERF
DIR_PERF = perf
endif

SUBDIRS = src $(DIR_P) $(DIR_R) $(DIR_PERF) devices bindings
DIST_SUBDIRS = src python ruby perf devices bindings

EXTRA_DIST =  $(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.bz2

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@
