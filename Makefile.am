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

SUBDIRS = src $(DIR_P) $(DIR_R) $(DIR_J) $(DIR_PERF)
DIST_SUBDIRS = src python ruby java perf

dist-hook:
		-rm -rf $(distdir)/third-party/openpgm/$pgm_basename
