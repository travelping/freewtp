-- Copyright 2008 Steven Barth <steven@midlink.org>
-- Copyright 2010-2015 Jo-Philipp Wich <jow@openwrt.org>
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.freewtp", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/wtp") then
		return
	end

	entry( {"admin", "services", "freewtp"}, cbi("freewtp/freewtp"), _("FreeWTP"), 90).leaf=true
end
