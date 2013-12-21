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

	int sock_util;

	struct capwap_list* devicelist;
};

/* Device handle */
struct nl80211_device_handle {
	struct nl80211_global_handle* globalhandle;

	uint32_t phyindex;
	char phyname[IFNAMSIZ];
};

/* WLAN handle */
struct nl80211_wlan_handle {
	struct nl80211_device_handle* devicehandle;

	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;

	uint32_t virtindex;
	char virtname[IFNAMSIZ];

	uint8_t address[ETH_ALEN];

	/* Beacon / Probe response */
	void* headbeacon;
	int headbeaconlength;
	void* tailbeacon;
	int tailbeaconlength;

	char ssid[WIFI_SSID_MAX_LENGTH + 1];
	uint32_t suppressssid;

	uint32_t beaconinterval;
	uint32_t dtimperiod;

	uint32_t authenticationtype;
};

/* Physical device info */
struct nl80211_phydevice_item {
	uint32_t index;
	char name[IFNAMSIZ];
};

/* Virtual device info */
struct nl80211_virtdevice_item {
	uint32_t phyindex;
	uint32_t virtindex;
	char virtname[IFNAMSIZ];
};

#endif /* __WIFI_NL80211_HEADER__ */
