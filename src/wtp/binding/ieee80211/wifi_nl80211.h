#ifndef __WIFI_NL80211_HEADER__
#define __WIFI_NL80211_HEADER__

#include "capwap_hash.h"
#include "netlink_link.h"

/* Compatibility functions */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
#endif

/* */
typedef int (*nl_valid_cb)(struct nl_msg* msg, void* data);

/* Global handle */
struct nl80211_global_handle {
	struct nl_sock* nl;
	struct nl_cb* nl_cb;
	int nl80211_id;

	struct nl_sock* nl_event;
	int nl_event_fd;

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

	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;

	uint64_t last_cookie;
};

#endif /* __WIFI_NL80211_HEADER__ */
