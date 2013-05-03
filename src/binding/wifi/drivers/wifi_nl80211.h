#ifndef __WIFI_NL80211_HEADER__
#define __WIFI_NL80211_HEADER__

/* Compatibility functions */
#if !defined(HAVE_LIBNL20) && !defined(HAVE_LIBNL30)
#define nl_sock nl_handle
#endif

/* */
typedef int (*nl_valid_cb)(struct nl_msg* msg, void* data);

/* Global handle */
struct nl80211_global_handle {
	struct nl_sock* nl;
	struct nl_cb* nl_cb;
	int nl80211_id;

	struct capwap_list* devicelist;
};

/* Device handle */
struct nl80211_device_handle {
	struct nl80211_global_handle* globalhandle;

	uint32_t phyindex;
	char phyname[IFNAMSIZ];
};

/* Physical device info */
struct nl80211_phydevice_item {
	uint32_t index;
	char name[IFNAMSIZ];
};

#endif /* __WIFI_NL80211_HEADER__ */
