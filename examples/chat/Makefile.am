INCLUDES = -I$(top_builddir)/bindings/c -I$(top_builddir)/bindings/cpp

noinst_PROGRAMS = display prompt

display_SOURCES = display.cpp
display_LDADD = $(top_builddir)/src/libzmq.la
display_CXXFLAGS = -Wall -pedantic -Werror

prompt_SOURCES = prompt.cpp 
prompt_LDADD = $(top_builddir)/src/libzmq.la
prompt_CXXFLAGS = -Wall -pedantic -Werror
