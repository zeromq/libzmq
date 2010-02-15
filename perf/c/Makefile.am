INCLUDES = -I$(top_builddir)/bindings/c

if BUILD_PGM_EXAMPLES
PGM_EXAMPLES_BINS = pgmsend pgmrecv
endif

noinst_PROGRAMS = local_lat remote_lat local_thr remote_thr $(PGM_EXAMPLES_BINS)

local_lat_LDADD = $(top_builddir)/src/libzmq.la
local_lat_SOURCES = local_lat.c
local_lat_CXXFLAGS = -Wall -pedantic -Werror

remote_lat_LDADD = $(top_builddir)/src/libzmq.la
remote_lat_SOURCES = remote_lat.c
remote_lat_CXXFLAGS = -Wall -pedantic -Werror

local_thr_LDADD = $(top_builddir)/src/libzmq.la
local_thr_SOURCES = local_thr.c
local_thr_CXXFLAGS = -Wall -pedantic -Werror

remote_thr_LDADD = $(top_builddir)/src/libzmq.la
remote_thr_SOURCES = remote_thr.c
remote_thr_CXXFLAGS = -Wall -pedantic -Werror

if BUILD_PGM_EXAMPLES

if ON_MINGW
pgmexamples_diff_flags = \
    -D_WIN32_WINNT=0x0501 \
    -DCONFIG_HAVE_IFR_NETMASK \
    -DCONFIG_BIND_INADDR_ANY \
    -DCONFIG_GALOIS_MUL_LUT \
    -DIF_NAMESIZE=256 \
    -DPGM_GNUC_INTERNAL=G_GNUC_INTERNAL \
    -DCONFIG_HAVE_WSACMSGHDR \
    -DGETTEXT_PACKAGE='"pgm"' \
    -DG_LOG_DOMAIN='"Pgm"'

else
pgmexamples_diff_flags = \
    -D__need_IOV_MAX \
    -DCONFIG_HAVE_PSELECT \
    -DCONFIG_HAVE_POLL \
    -DCONFIG_HAVE_PPOLL \
    -DCONFIG_HAVE_EPOLL \
    -DCONFIG_HAVE_CLOCK_GETTIME \
    -DCONFIG_HAVE_CLOCK_NANOSLEEP \
    -DCONFIG_HAVE_NANOSLEEP \
    -DCONFIG_HAVE_USLEEP \
    -DCONFIG_HAVE_RTC \
    -DCONFIG_HAVE_TSC \
    -DCONFIG_HAVE_IFR_NETMASK \
    -DCONFIG_HAVE_GETIFADDRS \
    -DCONFIG_HAVE_GETHOSTBYNAME2 \
    -DCONFIG_HAVE_GETPROTOBYNAME_R \
    -DCONFIG_BIND_INADDR_ANY \
    -DCONFIG_GALOIS_MUL_LUT \
    -DCONFIG_HAVE_MCAST_JOIN \
    -DCONFIG_HAVE_IP_MREQN \
    -DCONFIG_HAVE_SPRINTF_GROUPING \
    -DCONFIG_HAVE_HPET \
    -DPGM_GNUC_INTERNAL=G_GNUC_INTERNAL \
    -DGETTEXT_PACKAGE='"pgm"' \
    -DG_LOG_DOMAIN='"Pgm"'
endif

pgmsend_SOURCES = ../../foreign/openpgm/@pgm_basename@/openpgm/pgm/examples/pgmsend.c
pgmsend_LDADD = $(top_builddir)/src/libzmq.la
pgmsend_CFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ -Wall @LIBZMQ_EXTRA_CXXFLAGS@ \
    -pipe \
    -Wall \
    -Wextra \
    -Wfloat-equal \
    -Wshadow \
    -Wunsafe-loop-optimizations \
    -Wpointer-arith \
    -Wbad-function-cast \
    -Wcast-qual \
    -Wcast-align \
    -Wwrite-strings \
    -Waggregate-return \
    -Wstrict-prototypes \
    -Wold-style-definition \
    -Wmissing-prototypes \
    -Wmissing-declarations \
    -Wmissing-noreturn \
    -Wmissing-format-attribute \
    -Wredundant-decls \
    -Wnested-externs \
    -Winline \
    -pedantic \
    -std=gnu99 \
    --param max-inline-insns-single=600 \
    -D_REENTRANT \
    -D_GNU_SOURCE \
    ${pgmexamples_diff_flags}

pgmrecv_SOURCES = ../../foreign/openpgm/@pgm_basename@/openpgm/pgm/examples/pgmrecv.c
pgmrecv_LDADD = $(top_builddir)/src/libzmq.la
pgmrecv_CFLAGS = -I$(top_srcdir)/foreign/openpgm/@pgm_basename@/openpgm/pgm/include/ -Wall @LIBZMQ_EXTRA_CXXFLAGS@ \
    -pipe \
    -Wall \
    -Wextra \
    -Wfloat-equal \
    -Wshadow \
    -Wunsafe-loop-optimizations \
    -Wpointer-arith \
    -Wbad-function-cast \
    -Wcast-qual \
    -Wcast-align \
    -Wwrite-strings \
    -Waggregate-return \
    -Wstrict-prototypes \
    -Wold-style-definition \
    -Wmissing-prototypes \
    -Wmissing-declarations \
    -Wmissing-noreturn \
    -Wmissing-format-attribute \
    -Wredundant-decls \
    -Wnested-externs \
    -Winline \
    -pedantic \
    -std=gnu99 \
    --param max-inline-insns-single=600 \
    -D_REENTRANT \
    -D_GNU_SOURCE \
    ${pgmexamples_diff_flags}

endif
