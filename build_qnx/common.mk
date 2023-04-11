ifndef QCONFIG
QCONFIG=qconfig.mk
endif
include $(QCONFIG)

NAME=libzmq

#$(INSTALL_ROOT_$(OS)) is pointing to $QNX_TARGET
#by default, unless it was manually re-routed to
#a staging area by setting both INSTALL_ROOT_nto
#and USE_INSTALL_ROOT
LIBZMQ_INSTALL_ROOT ?= $(INSTALL_ROOT_$(OS))

LIBZMQ_VERSION = .4.3.4

#choose Release or Debug
CMAKE_BUILD_TYPE ?= Release

#override 'all' target to bypass the default QNX build system
ALL_DEPENDENCIES = libzmq_all
.PHONY: libzmq_all install check clean

CFLAGS += $(FLAGS)
LDFLAGS += -Wl,--build-id=md5

include $(MKFILES_ROOT)/qtargets.mk

LIBZMQ_DIR = $(PROJECT_ROOT)/../

CMAKE_ARGS = -DCMAKE_TOOLCHAIN_FILE=$(PROJECT_ROOT)/qnx.nto.toolchain.cmake \
             -DCMAKE_INSTALL_PREFIX=$(LIBZMQ_INSTALL_ROOT)/${CPUVARDIR}/usr \
             -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
             -DEXTRA_CMAKE_C_FLAGS="$(CFLAGS)" \
             -DEXTRA_CMAKE_CXX_FLAGS="$(CFLAGS)" \
             -DEXTRA_CMAKE_ASM_FLAGS="$(FLAGS)" \
             -DEXTRA_CMAKE_LINKER_FLAGS="$(LDFLAGS)" \
             -DCMAKE_INSTALL_INCLUDEDIR=$(LIBZMQ_INSTALL_ROOT)/usr/include \
             -DCMAKE_INSTALL_LIBDIR=$(LIBZMQ_INSTALL_ROOT)/$(CPUVARDIR)/usr/lib \
             -DCMAKE_INSTALL_BINDIR=$(LIBZMQ_INSTALL_ROOT)/$(CPUVARDIR)/usr/bin \
             -DCPUVARDIR=$(CPUVARDIR)

MAKE_ARGS ?= -j $(firstword $(JLEVEL) 1)

ifndef NO_TARGET_OVERRIDE
libzmq_all:
	@mkdir -p build
	@cd build && cmake $(CMAKE_ARGS) $(LIBZMQ_DIR)
	@cd build && make VERBOSE=1 all $(MAKE_ARGS)

install check: libzmq_all
	@cd build && make VERBOSE=1 install

clean iclean spotless:
	rm -rf build

uninstall:
endif
