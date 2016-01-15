# Copyright (C) [2011-2012] [TheClashingRocks.org]
#
# Author: Jiva Nath Bagale <jnbagale@gmail.com>
# author: Victor Perron <victor@iso3103.net>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# 
include $(TOPDIR)/rules.mk

PKG_NAME:=zeromq
PKG_VERSION:=3.2.2

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://download.zeromq.org/

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/zeromq
    MAINTAINER:=victor@iso3103.net
    TITLE:=zeromq
    SECTION:=libs
    DEPENDS:=+libstdcpp +libpthread +librt
    CATEGORY:=Libraries
    URL:=http://www.zeromq.org/
endef

define Package/zeromq/description
    The library provides light weight messaging services using an intelligent transport layer. 
    It can carry messages across inproc, IPC, TCP and multicast and is faster than TCP for 
    clustered products and supercomputing.
endef


define Build/InstallDev
	$(INSTALL_DIR) \
		$(1)/usr/lib 	\
		$(1)/usr/include \
		$(1)/usr/lib/pkgconfig
	$(CP) \
		$(PKG_INSTALL_DIR)/usr/lib/* \
		$(1)/usr/lib/
	$(CP) \
		$(PKG_INSTALL_DIR)/usr/include/* \
		$(1)/usr/include/
	$(CP) \
		$(PKG_INSTALL_DIR)/usr/lib/pkgconfig \
		$(1)/usr/lib/

endef

define Package/zeromq/install
	$(INSTALL_DIR) $(1)/usr/lib 
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/*.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,zeromq))

