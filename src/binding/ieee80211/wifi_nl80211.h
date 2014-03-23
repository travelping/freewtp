#ifndef __WIFI_NL80211_HEADER__
#define __WIFI_NL80211_HEADER__

#include "capwap_hash.h"
#include "netlink_link.h"

/* Compatibility functions */
#ifdef HAVE_LIBNL_10 
#define nl_sock nl_handle
#endif

/* */
#define WIFI_NL80211_STATIONS_HASH_SIZE			256
#define WIFI_NL80211_STATIONS_KEY_SIZE			ETH_ALEN

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

	struct capwap_list* devicelist;
	struct capwap_timeout* timeout;

	/* Stations */
	struct capwap_hash* stations;
};

/* Device handle */
#define NL80211_DEVICE_SET_FREQUENCY					0x00000001
#define NL80211_DEVICE_SET_RATES						0x00000002
#define NL80211_DEVICE_SET_CONFIGURATION				0x00000004

#define NL80211_DEVICE_REQUIRED_FOR_BSS					(NL80211_DEVICE_SET_FREQUENCY | NL80211_DEVICE_SET_RATES | NL80211_DEVICE_SET_CONFIGURATION)

struct nl80211_device_handle {
	struct nl80211_global_handle* globalhandle;

	uint32_t phyindex;
	char phyname[IFNAMSIZ];

	unsigned long flags;

	/* */
	struct capwap_list* wlanlist;
	unsigned long wlanactive;

	/* */
	uint16_t beaconperiod;
	uint8_t dtimperiod;
	int shortpreamble;

	/* */
	struct wifi_frequency currentfrequency;

	/* Cached capability */
	struct wifi_capability* capability;

	/* Rates */
	unsigned long supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];
	unsigned long basicratescount;
	uint8_t basicrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];

	/* ERP Information */
	int olbc;
	unsigned long stationsnonerpcount;
	unsigned long stationsnoshortslottimecount;
	unsigned long stationsnoshortpreamblecount;
};

/* WLAN handle */
#define NL80211_WLAN_RUNNING						0x00000001
#define NL80211_WLAN_SET_BEACON						0x00000002
#define NL80211_WLAN_OPERSTATE_RUNNING				0x00000004

struct nl80211_wlan_handle {
	struct nl80211_device_handle* devicehandle;

	struct nl_sock* nl;
	int nl_fd;
	struct nl_cb* nl_cb;

	unsigned long flags;

	uint32_t virtindex;
	char virtname[IFNAMSIZ];

	uint8_t address[ETH_ALEN];

	uint64_t last_cookie;

	/* */
	send_mgmtframe_to_ac send_mgmtframe;
	void* send_mgmtframe_to_ac_cbparam;

	/* WLAN information */
	char ssid[WIFI_SSID_MAX_LENGTH + 1];
	uint8_t ssid_hidden;
	uint16_t capability;

	/* Tunnel */
	uint8_t macmode;
	uint8_t tunnelmode;

	/* Authentication */
	uint8_t authenticationtype;

	/* Station information */
	unsigned long stationscount;
	unsigned long maxstationscount;

	uint32_t aidbitfield[IEEE80211_AID_BITFIELD_SIZE];
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

/* Station */
#define NL80211_STATION_FLAGS_AUTHENTICATED					0x00000001
#define NL80211_STATION_FLAGS_ASSOCIATE						0x00000002
#define NL80211_STATION_FLAGS_NON_ERP						0x00000004
#define NL80211_STATION_FLAGS_NO_SHORT_SLOT_TIME			0x00000008
#define NL80211_STATION_FLAGS_NO_SHORT_PREAMBLE				0x00000010
#define NL80211_STATION_FLAGS_WMM							0x00000020
#define NL80211_STATION_FLAGS_AUTHORIZED					0x00000040

/* */
#define NL80211_STATION_TIMEOUT_ASSOCIATION_COMPLETE		30000
#define NL80211_STATION_TIMEOUT_AFTER_DEAUTHENTICATED		5000

/* */
#define NL80211_STATION_TIMEOUT_ACTION_DELETE				0x00000001
#define NL80211_STATION_TIMEOUT_ACTION_DEAUTHENTICATE		0x00000002

/* */
struct nl80211_station {
	struct nl80211_global_handle* globalhandle;
	uint8_t address[ETH_ALEN];

	/* */
	struct nl80211_wlan_handle* wlanhandle;

	/* */
	unsigned long flags;

	/* Timers */
	int timeoutaction;
	unsigned long idtimeout;

	/* */
	uint16_t capability;
	uint16_t listeninterval;
	uint16_t aid;

	/* */
	int supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];

	/* Authentication */
	uint16_t authalgorithm;
};

#endif /* __WIFI_NL80211_HEADER__ */
