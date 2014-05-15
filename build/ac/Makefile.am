# SmartCAPWAP -- An Open Source CAPWAP WTP / AC
#
# Copyright (C) 2012-2013 Massimo Vellucci <vemax78@gmail.com>
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

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

bin_PROGRAMS = ac

AM_CFLAGS = \
	-DCAPWAP_MULTITHREADING_ENABLE \
	-D_REENTRANT \
	-D_GNU_SOURCE

AM_CFLAGS += $(LIBXML2_CFLAGS) \
	$(CYASSL_CFLAGS)

INCLUDES = \
	-I$(top_srcdir)/build \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/ac \
	-I$(top_srcdir)/src/common/binding/ieee80211 

include $(top_srcdir)/build/Makefile_common.am

ac_SOURCES = \
	$(capwap_SOURCES) \
	$(top_srcdir)/src/common/capwap_event.c \
	$(top_srcdir)/src/common/capwap_lock.c \
	$(top_srcdir)/src/common/capwap_rwlock.c \
	$(top_srcdir)/src/common/capwap_socket.c \
	$(top_srcdir)/src/ac/ac.c \
	$(top_srcdir)/src/ac/ac_backend.c \
	$(top_srcdir)/src/ac/ac_execute.c \
	$(top_srcdir)/src/ac/ac_session.c \
	$(top_srcdir)/src/ac/ac_session_data.c \
	$(top_srcdir)/src/ac/ac_wlans.c \
	$(top_srcdir)/src/ac/ac_ieee80211_data.c \
	$(top_srcdir)/src/ac/ac_discovery.c \
	$(top_srcdir)/src/ac/ac_80211_json.c \
	$(top_srcdir)/src/ac/ac_80211_json_addwlan.c \
	$(top_srcdir)/src/ac/ac_80211_json_antenna.c \
	$(top_srcdir)/src/ac/ac_80211_json_assignbssid.c \
	$(top_srcdir)/src/ac/ac_80211_json_deletewlan.c \
	$(top_srcdir)/src/ac/ac_80211_json_directsequencecontrol.c \
	$(top_srcdir)/src/ac/ac_80211_json_ie.c \
	$(top_srcdir)/src/ac/ac_80211_json_macoperation.c \
	$(top_srcdir)/src/ac/ac_80211_json_miccountermeasures.c \
	$(top_srcdir)/src/ac/ac_80211_json_multidomaincapability.c \
	$(top_srcdir)/src/ac/ac_80211_json_ofdmcontrol.c \
	$(top_srcdir)/src/ac/ac_80211_json_rateset.c \
	$(top_srcdir)/src/ac/ac_80211_json_rsnaerrorreport.c \
	$(top_srcdir)/src/ac/ac_80211_json_statistics.c \
	$(top_srcdir)/src/ac/ac_80211_json_supportedrates.c \
	$(top_srcdir)/src/ac/ac_80211_json_txpower.c \
	$(top_srcdir)/src/ac/ac_80211_json_txpowerlevel.c \
	$(top_srcdir)/src/ac/ac_80211_json_updatewlan.c \
	$(top_srcdir)/src/ac/ac_80211_json_wtpqos.c \
	$(top_srcdir)/src/ac/ac_80211_json_wtpradioconf.c \
	$(top_srcdir)/src/ac/ac_80211_json_wtpradiofailalarm.c \
	$(top_srcdir)/src/ac/ac_80211_json_wtpradioinformation.c \
	$(top_srcdir)/src/ac/ac_dfa_join.c \
	$(top_srcdir)/src/ac/ac_dfa_configure.c \
	$(top_srcdir)/src/ac/ac_dfa_imagedata.c \
	$(top_srcdir)/src/ac/ac_dfa_datacheck.c \
	$(top_srcdir)/src/ac/ac_dfa_dtls.c \
	$(top_srcdir)/src/ac/ac_dfa_run.c \
	$(top_srcdir)/src/ac/ac_dfa_reset.c \
	$(top_srcdir)/src/ac/ac_dfa_teardown.c \
	$(top_srcdir)/src/ac/ac_soap.c \
	$(top_srcdir)/src/common/binding/ieee80211/ieee80211.c

ac_LDADD = \
	$(CONFIG_LIBS) \
	$(PTHREAD_LIBS) \
	$(LIBXML2_LIBS) \
	$(LIBJSON_LIBS) \
	$(CYASSL_LIBS)
