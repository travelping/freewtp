#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=smartcapwap
PKG_VERSION:=1.2.1
PKG_RELEASE:=1

SRC_SMARTCAPWAP := /usr/src/tplino/components/smartcapwap
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=git://github.com/travelping/smartcapwap.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=v1.2.1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_MAINTAINER:=Travelping GmbH <info@travelping.com>

PKG_LICENSE:=GPL-v2
PKG_LICENSE_FILES:=LICENSE

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

ifneq ($(findstring c,$(OPENWRT_VERBOSE)),)
  SMARTCAPWAP_MAKE_VERBOSE := V=1
else
  SMARTCAPWAP_MAKE_VERBOSE :=
endif

define Package/smartcapwap
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SmartCAPWAP WTP
  MAINTAINER:=Massimo Vellucci <vemax78@gmail.com>
  DEPENDS:=+libnl +libev +libconfig +libcyassl +kmod-smartcapwap
endef

define Package/smartcapwap/description
	This package contains the SmartCAPWAP WTP daemon.
endef

define Package/smartcapwap/conffiles
/etc/capwap/wtp.conf
/etc/capwap/ca.crt
/etc/capwap/wtp.crt
/etc/capwap/wtp.key
endef

define KernelPackage/smartcapwap
  SUBMENU:=Network Support
  TITLE:=SmartCAPWAP Data Channel Module
  MAINTAINER:=Massimo Vellucci <vemax78@gmail.com>
  DEPENDS:=+kmod-mac80211 +kmod-udptunnel4 +IPV6:kmod-udptunnel6
  FILES:=$(PKG_BUILD_DIR)/src/wtp/kmod/smartcapwap.ko
  AUTOLOAD:=$(call AutoLoad,70,smartcapwap)
endef

define KernelPackage/smartcapwap/description
	This package contains the SmartCAPWAP Data Transport kernel module.
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -r $(SRC_SMARTCAPWAP)/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
	$(call Build/Configure/Default, --disable-ac)
endef

define Build/Compile/wtp
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		all
endef

define Build/Compile/kmod
	$(MAKE) -C "$(LINUX_DIR)" \
		CROSS_COMPILE="$(KERNEL_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)/src/wtp/kmod" \
		KLIB_BUILD="$(LINUX_DIR)" \
		KLIB="$(TARGET_MODULES_DIR)" \
		KBUILD_EXTRA_SYMBOLS="$(LINUX_DIR)/../compat-wireless-2014-11-04/Module.symvers" \
		LINUXINCLUDE="-I$(STAGING_DIR)/usr/include/mac80211-backport/uapi \
			-I$(STAGING_DIR)/usr/include/mac80211-backport \
			-I$(STAGING_DIR)/usr/include/mac80211/uapi \
			-I$(STAGING_DIR)/usr/include/mac80211 \
			-I$(LINUX_DIR)/arch/$(LINUX_KARCH)/include \
			-Iarch/$(LINUX_KARCH)/include/generated \
			-Iinclude \
			-I$(LINUX_DIR)/arch/$(LINUX_KARCH)/include/uapi \
			-Iarch/$(LINUX_KARCH)/include/generated/uapi \
			-I$(LINUX_DIR)/include/uapi \
			-Iinclude/generated/uapi \
			-include $(LINUX_DIR)/include/linux/kconfig.h \
			-include $(STAGING_DIR)/usr/include/mac80211-backport/backport/backport.h" \
		$(SMARTCAPWAP_MAKE_VERBOSE) \
		modules
endef

define Build/Compile
	$(Build/Compile/wtp)
	$(Build/Compile/kmod)
endef

define Package/smartcapwap/install
	$(INSTALL_DIR) $(1)/etc/capwap
	$(INSTALL_CONF) ./files/wtp.conf $(1)/etc/capwap/wtp.conf
	$(INSTALL_CONF) ./files/ca.crt $(1)/etc/capwap/ca.crt
	$(INSTALL_CONF) ./files/wtp.crt $(1)/etc/capwap/wtp.crt
	$(INSTALL_CONF) ./files/wtp.key $(1)/etc/capwap/wtp.key
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/build/wtp/wtp $(1)/usr/bin
endef

$(eval $(call BuildPackage,smartcapwap))
$(eval $(call KernelPackage,smartcapwap))
