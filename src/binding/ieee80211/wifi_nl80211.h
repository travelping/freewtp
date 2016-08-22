#ifndef __WIFI_NL80211_HEADER__
#define __WIFI_NL80211_HEADER__

#include <ev.h>

#include "hash.h"
#include "netlink_link.h"

/* Compatibility functions */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
#endif

#define WMM_QOSINFO_STA_AC_MASK 0x0f
#define WMM_QOSINFO_STA_SP_MASK 0x03
#define WMM_QOSINFO_STA_SP_SHIFT 5

/* */
typedef int (*nl_valid_cb)(struct nl_msg* msg, void* data);

/* Global handle */
struct nl80211_global_handle {
	int nl80211_id;

	struct nl_sock* nl;
	struct nl_cb* nl_cb;

	struct nl_sock *nl_event;
	ev_io nl_event_ev;

	struct netlink* netlinkhandle;

	int sock_util;
};

/* Device handle */
struct nl80211_device_handle {
	struct nl80211_global_handle* globalhandle;
};

/* WLAN handle */
struct nl80211_wlan_handle {
	struct nl80211_device_handle* devicehandle;

	struct nl_sock *nl;
	ev_io nl_ev;
	struct nl_cb *nl_cb;

	uint64_t last_cookie;
};

/* NL80211 Station statistics */
struct nl80211_station_data {
        unsigned long rx_packets, tx_packets;
        unsigned long long rx_bytes, tx_bytes;
        int bytes_64bit;
        unsigned long inactive_msec;
        unsigned long tx_retry_failed;
};

#endif /* __WIFI_NL80211_HEADER__ */
