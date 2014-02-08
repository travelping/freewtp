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

bin_PROGRAMS = wtp

AM_CFLAGS = \
	-D_REENTRANT \
	-D_GNU_SOURCE

if DTLS_ENABLED
AM_CFLAGS += $(SSL_CFLAGS)
endif

INCLUDES = \
	-I$(top_srcdir)/build \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/wtp \
	-I$(top_srcdir)/src/binding/ieee80211 

include $(top_srcdir)/build/Makefile_common.am

wtp_SOURCES = \
	$(capwap_SOURCES) \
	$(top_srcdir)/src/wtp/wtp.c \
	$(top_srcdir)/src/wtp/wtp_element_helper.c \
	$(top_srcdir)/src/wtp/wtp_dfa.c \
	$(top_srcdir)/src/wtp/wtp_dfa_idle.c \
	$(top_srcdir)/src/wtp/wtp_dfa_discovery.c \
	$(top_srcdir)/src/wtp/wtp_dfa_sulking.c \
	$(top_srcdir)/src/wtp/wtp_dfa_dtls.c \
	$(top_srcdir)/src/wtp/wtp_dfa_join.c \
	$(top_srcdir)/src/wtp/wtp_dfa_configure.c \
	$(top_srcdir)/src/wtp/wtp_dfa_datacheck.c \
	$(top_srcdir)/src/wtp/wtp_dfa_run.c \
	$(top_srcdir)/src/wtp/wtp_dfa_reset.c \
	$(top_srcdir)/src/wtp/wtp_dfa_imagedata.c \
	$(top_srcdir)/src/wtp/wtp_radio.c \
	$(top_srcdir)/src/binding/ieee80211/ieee80211.c \
	$(top_srcdir)/src/binding/ieee80211/netlink_link.c \
	$(top_srcdir)/src/binding/ieee80211/wifi_drivers.c

wtp_LDADD = \
	$(CONFIG_LIBS)

if DTLS_ENABLED
wtp_LDADD += $(SSL_LIBS)
endif

if BUILD_WTP_WIFI_DRIVERS_NL80211
wtp_SOURCES += $(top_srcdir)/src/binding/ieee80211/wifi_nl80211.c
AM_CFLAGS += ${LIBNL_CFLAGS}
wtp_LDADD += $(LIBNL_LIBS)
endif

