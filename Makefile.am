if BUILD_PYTHON
DIR_P = python
endif

if BUILD_RUBY
DIR_R = ruby
endif

if BUILD_JAVA
DIR_J = java
endif

if BUILD_PERF
DIR_PERF = perf
endif

SUBDIRS = src $(DIR_P) $(DIR_R) $(DIR_J) $(DIR_PERF) devices
DIST_SUBDIRS = src python ruby java perf devices

EXTRA_DIST =  $(top_srcdir)/foreign/openpgm/@pgm_basename@.tar.bz2

dist-hook:
		-rm -rf $(distdir)/foreign/openpgm/@pgm_basename@
