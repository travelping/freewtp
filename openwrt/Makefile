#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=smartcapwap
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

PKG_FIXUP:=autoreconf

include $(INCLUDE_DIR)/package.mk

define Package/smartcapwap
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SmartCAPWAP WTP
  MAINTAINER:=Massimo Vellucci <vemax78@gmail.com>
  DEPENDS:=+libnl-tiny +libconfig +libcyassl +kmod-smartcapwap
endef

define Package/smartcapwap/description
	This package contains the SmartCAPWAP WTP daemon.
endef

define KernelPackage/smartcapwap
  SUBMENU:=Network Support
  TITLE:=SmartCAPWAP Data Channel Module
  MAINTAINER:=Massimo Vellucci <vemax78@gmail.com>
  DEPENDS:=+kmod-mac80211
  FILES:=$(PKG_BUILD_DIR)/src/kmod/smartcapwap.ko
  AUTOLOAD:=$(call AutoLoad,70,smartcapwap)
endef

define KernelPackage/smartcapwap/description
	This package contains the SmartCAPWAP Data Transport kernel module.
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl-tiny
SRC_SMARTCAPWAP:=/mnt/hgfs/shared/smartcapwap

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
		SUBDIRS="$(PKG_BUILD_DIR)/src/kmod" \
		KLIB_BUILD="$(LINUX_DIR)" \
		KLIB="$(TARGET_MODULES_DIR)" \
		KBUILD_EXTRA_SYMBOLS="$(LINUX_DIR)/../compat-wireless-2014-03-31/Module.symvers" \
		LINUXINCLUDE="-I$(STAGING_DIR)/usr/include/mac80211-backport \
			-I$(LINUX_DIR)/arch/x86/include \
			-Iarch/x86/include/generated \
			-Iinclude \
			-I$(LINUX_DIR)/arch/x86/include/uapi \
			-Iarch/x86/include/generated/uapi \
			-I$(LINUX_DIR)/include/uapi \
			-Iinclude/generated/uapi \
			-include $(LINUX_DIR)/include/linux/kconfig.h \
			-include $(STAGING_DIR)/usr/include/mac80211-backport/backport/backport.h \
		" \
		V="$(V)" \
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
