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

bin_PROGRAMS = wtp

AM_CFLAGS = -std=gnu99 -D_GNU_SOURCE \
	    -fno-strict-aliasing \
	    ${LIBNL_CFLAGS}

if DTLS_ENABLED
AM_CFLAGS += $(WOLFSSL_CFLAGS)
endif

AM_CFLAGS += \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/kmod \
	-I$(top_srcdir)/lib/binding/ieee80211 \
	-I$(top_srcdir)/src/binding/ieee80211

wtp_SOURCES = \
	wtp.c \
	kmod.c \
	element_helper.c \
	dfa.c \
	dfa_idle.c \
	dfa_discovery.c \
	dfa_sulking.c \
	dfa_dtls.c \
	dfa_join.c \
	dfa_configure.c \
	dfa_datacheck.c \
	dfa_run.c \
	dfa_reset.c \
	dfa_imagedata.c \
	radio.c \
	binding/ieee80211/netlink_link.c \
	binding/ieee80211/wifi_drivers.c

if BUILD_WTP_WIFI_DRIVERS_NL80211
wtp_SOURCES += binding/ieee80211/wifi_nl80211.c
endif

wtp_LDADD = $(CONFIG_LIBS) \
	$(LIBNL_LIBS) \
	$(top_builddir)/lib/libcapwap.la

if DTLS_ENABLED
wtp_LDADD += $(WOLFSSL_LIBS)
endif
