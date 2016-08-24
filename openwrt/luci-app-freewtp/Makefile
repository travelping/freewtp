#
# Copyright (C) 2016 Travelping GmbH
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-freewtp
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-freewtp
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=FreeWTP CAPWAP WTP
	URL:=https://github.com/travelping/freewtp
	MAINTAINER:=Travelping GmbH <info@travelping.com>
	DEPENDS:=+freewtp +luci-base
endef

define Package/luci-app-freewtp/description
	This package allows you to configure the FreeWTP CAPWAP WTP
endef

define Build/Compile
endef

define Package/luci-app-freewtp/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci
	$(CP) ./luasrc/* $(1)/usr/lib/lua/luci
endef

$(eval $(call BuildPackage,luci-app-freewtp))
