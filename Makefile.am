include_HEADERS = include/zmq.h include/zmq.hpp


if BUILD_PYTHON
DIR_P = python
endif

if BUILD_RUBY
DIR_R = ruby
endif

SUBDIRS = src examples $(DIR_P) $(DIR_R)
DIST_SUBDIRS = src examples $(DIR_P) $(DIR_R)
