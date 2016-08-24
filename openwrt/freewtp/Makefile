#
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=freewtp
PKG_VERSION:=1.4.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/travelping/freewtp.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=a631f89729604f77a4907e5597bf15dd916f1e33
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_MAINTAINER:=Travelping GmbH <info@travelping.com>

PKG_LICENSE:=GPL-v2
PKG_LICENSE_FILES:=LICENSE

PKG_FIXUP:=autoreconf

PKG_BUILD_DEPENDS:=mac80211
STAMP_CONFIGURED_DEPENDS := $(STAGING_DIR)/usr/include/mac80211-backport/backport/autoconf.h

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define Package/freewtp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Freewtp WTP
  MAINTAINER:=Travelping GmbH <info@travelping.com>
  DEPENDS:=+libnl +libev +libconfig +libcyassl +kmod-freewtp \
	   +@CYASSL_HAS_DTLS +@CYASSL_HAS_AES_CCM +@CYASSL_HAS_AES_GCM \
	   +@CYASSL_HAS_CHACHA +@CYASSL_HAS_ECC +@CYASSL_HAS_DH \
	   +@CYASSL_HAS_PSK +@CYASSL_HAS_ECC25519 +@CYASSL_HAS_POLY_1305
endef

define Package/freewtp/description
	This package contains the Freewtp WTP daemon.
endef

define KernelPackage/freewtp
  SUBMENU:=Network Support
  TITLE:=Freewtp Data Channel Module
  MAINTAINER:=Travelping GmbH <info@travelping.com>
  DEPENDS:=+kmod-mac80211 +kmod-iptunnel +kmod-udptunnel4 +IPV6:kmod-udptunnel6 \
	   +@PACKAGE_MAC80211_CAPWAP_WTP
  FILES:=$(PKG_BUILD_DIR)/kmod/wtp.ko
  AUTOLOAD:=$(call AutoLoad,70,wtp)
endef

define KernelPackage/freewtp/description
	This package contains the Freewtp Data Transport kernel module.
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl3

define Build/Compile/wtp
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		all
endef

NOSTDINC_FLAGS = \
        -I$(PKG_BUILD_DIR)/kmod \
        -I$(STAGING_DIR)/usr/include/mac80211-backport \
        -I$(STAGING_DIR)/usr/include/mac80211/uapi \
        -I$(STAGING_DIR)/usr/include/mac80211 \
        -include backport/autoconf.h \
        -include backport/backport.h \
        -DCPTCFG_MAC80211_CAPWAP_WTP

define Build/Compile/kmod
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" \
		ARCH="$(LINUX_KARCH)" \
		CROSS_COMPILE="$(KERNEL_CROSS)" \
		SUBDIRS="$(PKG_BUILD_DIR)/kmod" \
		NOSTDINC_FLAGS="$(NOSTDINC_FLAGS)" \
		modules
endef

define Build/Compile
	$(Build/Compile/wtp)
	$(Build/Compile/kmod)
endef

define Package/freewtp/conffiles
/etc/wtp/
endef

define Package/freewtp/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/wtp.config $(1)/etc/config/wtp
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/wtp.init $(1)/etc/init.d/wtp
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/wtp $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/wtp
endef

$(eval $(call BuildPackage,freewtp))
$(eval $(call KernelPackage,freewtp))
