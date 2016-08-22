# FreeWTP -- An Open Source CAPWAP WTP
#
# Copyright SmartCAPWAP (C) 2012-2013 Massimo Vellucci <vemax78@gmail.com>
# Copyright FreeCAPWAP (C) 2016 Travelping GmbH <info@travelping.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING included with this
# distribution); if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

AM_CFLAGS = -std=gnu99 -D_GNU_SOURCE

noinst_LTLIBRARIES = libcapwap.la

libcapwap_la_LIBADD = -lwolfssl
libcapwap_la_SOURCES = \
	capwap.c \
	network.c \
	protocol.c \
	logging.c \
	list.c \
	array.c \
	hash.c \
	dtls.c \
	dfa.c \
	binding/ieee80211/ieee80211.c \
	element.c \
	element_acdescriptor.c \
	element_acipv4list.c \
	element_acipv6list.c \
	element_acname.c \
	element_acnamepriority.c \
	element_actimestamp.c \
	element_addmacacl.c \
	element_addstation.c \
	element_controlipv4.c \
	element_controlipv6.c \
	element_datatransferdata.c \
	element_datatransfermode.c \
	element_decrypterrorreport.c \
	element_decrypterrorreportperiod.c \
	element_deletemacacl.c \
	element_deletestation.c \
	element_discoverytype.c \
	element_duplicateipv4.c \
	element_duplicateipv6.c \
	element_ecnsupport.c \
	element_idletimeout.c \
	element_imagedata.c \
	element_imageidentifier.c \
	element_imageinfo.c \
	element_initdownload.c \
	element_localipv4.c \
	element_localipv6.c \
	element_location.c \
	element_maximumlength.c \
	element_mtudiscovery.c \
	element_radioadmstate.c \
	element_radiooprstate.c \
	element_resultcode.c \
	element_returnedmessage.c \
	element_sessionid.c \
	element_statisticstimer.c \
	element_timers.c \
	element_transport.c \
	element_vendorpayload.c \
	element_wtpboarddata.c \
	element_wtpdescriptor.c \
	element_wtpfallback.c \
	element_wtpframetunnelmode.c \
	element_wtpmactype.c \
	element_wtpname.c \
	element_wtpradiostat.c \
	element_wtprebootstat.c \
	element_wtpstaticipaddress.c \
	element_80211_addwlan.c \
	element_80211_antenna.c \
	element_80211_assignbssid.c \
	element_80211_deletewlan.c \
	element_80211_directsequencecontrol.c \
	element_80211_ie.c \
	element_80211_mac_profile.c \
	element_80211_macoperation.c \
	element_80211_miccountermeasures.c \
	element_80211_multidomaincapability.c \
	element_80211_ofdmcontrol.c \
	element_80211_rateset.c \
	element_80211_rsnaerrorreport.c \
	element_80211_station.c \
	element_80211_stationkey.c \
	element_80211_stationqos.c \
	element_80211_statistics.c \
	element_80211_supported_mac_profiles.c \
	element_80211_supportedrates.c \
	element_80211_txpower.c \
	element_80211_txpowerlevel.c \
	element_80211_updatestationqos.c \
	element_80211_updatewlan.c \
	element_80211_wtpqos.c \
	element_80211_wtpradioconf.c \
	element_80211_wtpradiofailalarm.c \
	element_80211_wtpradioinformation.c \
	element_80211n_radioconf.c \
	element_80211n_station_information.c \
	element_vendor_travelping_wtp_timestamp.c \
	element_vendor_travelping_80211_encryption_capability.c \
	element_vendor_travelping_80211_update_key.c

noinst_HEADERS = \
	error.h \
	rfc.h \
	capwap.h \
	network.h \
	protocol.h \
	logging.h \
	list.h \
	array.h \
	hash.h \
	dtls.h \
	capwap_dfa.h \
	binding/ieee80211/ieee80211.c \
	element.h \
	element_acdescriptor.h \
	element_acipv4list.h \
	element_acipv6list.h \
	element_acname.h \
	element_acnamepriority.h \
	element_actimestamp.h \
	element_addmacacl.h \
	element_addstation.h \
	element_controlipv4.h \
	element_controlipv6.h \
	element_datatransferdata.h \
	element_datatransfermode.h \
	element_decrypterrorreport.h \
	element_decrypterrorreportperiod.h \
	element_deletemacacl.h \
	element_deletestation.h \
	element_discoverytype.h \
	element_duplicateipv4.h \
	element_duplicateipv6.h \
	element_ecnsupport.h \
	element_idletimeout.h \
	element_imagedata.h \
	element_imageidentifier.h \
	element_imageinfo.h \
	element_initdownload.h \
	element_localipv4.h \
	element_localipv6.h \
	element_location.h \
	element_maximumlength.h \
	element_mtudiscovery.h \
	element_radioadmstate.h \
	element_radiooprstate.h \
	element_resultcode.h \
	element_returnedmessage.h \
	element_sessionid.h \
	element_statisticstimer.h \
	element_timers.h \
	element_transport.h \
	element_vendorpayload.h \
	element_wtpboarddata.h \
	element_wtpdescriptor.h \
	element_wtpfallback.h \
	element_wtpframetunnelmode.h \
	element_wtpmactype.h \
	element_wtpname.h \
	element_wtpradiostat.h \
	element_wtprebootstat.h \
	element_wtpstaticipaddress.h \
	element_80211_addwlan.h \
	element_80211_antenna.h \
	element_80211_assignbssid.h \
	element_80211_deletewlan.h \
	element_80211_directsequencecontrol.h \
	element_80211_ie.h \
	element_80211_macoperation.h \
	element_80211_mac_profile.h \
	element_80211_miccountermeasures.h \
	element_80211_multidomaincapability.h \
	element_80211_ofdmcontrol.h \
	element_80211_rateset.h \
	element_80211_rsnaerrorreport.h \
	element_80211_station.h \
	element_80211_stationkey.h \
	element_80211_stationqos.h \
	element_80211_statistics.h \
	element_80211_supported_mac_profiles.h \
	element_80211_supportedrates.h \
	element_80211_txpower.h \
	element_80211_txpowerlevel.h \
	element_80211_updatestationqos.h \
	element_80211_updatewlan.h \
	element_80211_wtpqos.h \
	element_80211_wtpradioconf.h \
	element_80211_wtpradiofailalarm.h \
	element_80211_wtpradioinformation.h \
	element_80211n_radioconf.h \
	element_80211n_station_information.h \
	element_vendor_travelping_wtp_timestamp.h \
	element_vendor_travelping_80211_encryption_capability.h \
	element_vendor_travelping_80211_update_key.h \
	vendor_travelping.h

if DEBUG_BUILD
libcapwap_la_SOURCES += debug.c
noinst_HEADERS += debug.h
endif
