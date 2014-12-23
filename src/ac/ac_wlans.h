#ifndef __AC_WLANS_HEADER__
#define __AC_WLANS_HEADER__

#include "ieee80211.h"

/* */
#define RADIOID_ANY						0

/* */
#define AC_WLANS_STATIONS_HASH_SIZE		256
#define AC_WLANS_STATIONS_KEY_SIZE		MACADDRESS_EUI48_LENGTH

/* AC WLAN */
struct ac_wlan {
	struct capwap_list_item* wlanitem;
	struct ac_device* device;

	uint8_t address[MACADDRESS_EUI48_LENGTH];
	uint8_t wlanid;

	/* CAPWAP Session */
	struct ac_session_t* session;

	uint32_t aidbitfield[IEEE80211_AID_BITFIELD_SIZE];

	/* Stations reference */
	struct capwap_list* stations;

	/* Capability */
	uint16_t capability;
	uint8_t keyindex;
	uint8_t keystatus;
	uint16_t keylength;
	uint8_t* key;
	uint8_t grouptsc[CAPWAP_ADD_WLAN_GROUPTSC_LENGTH];
	uint8_t qos;
	uint8_t authmode;
	uint8_t macmode;
	uint8_t tunnelmode;
	uint8_t suppressssid;
	char ssid[IEEE80211_SSID_MAX_LENGTH + 1];
};

/* */
struct ac_device {
	uint8_t radioid;
	struct capwap_list* wlans;

	/* Rates */
	unsigned long supportedratescount;
	uint8_t supportedrates[IEEE80211_SUPPORTEDRATE_MAX_COUNT];
};

/* */
struct ac_wlans {
	struct ac_device devices[RADIOID_MAX_COUNT];

	/* Stations */
	struct capwap_hash* stations;
};

/* */
#define AC_STATION_TIMEOUT_ASSOCIATION_COMPLETE			30000

/* */
#define AC_STATION_TIMEOUT_ACTION_DEAUTHENTICATE		0x00000001

/* */
#define AC_STATION_FLAGS_ENABLED						0x00000001
#define AC_STATION_FLAGS_AUTHENTICATED					0x00000002
#define AC_STATION_FLAGS_ASSOCIATE						0x00000004
#define AC_STATION_FLAGS_AUTHORIZED						0x00000008

/* AC Station */
struct ac_station {
	uint8_t address[MACADDRESS_EUI48_LENGTH];
	char addrtext[CAPWAP_MACADDRESS_EUI48_BUFFER];

	/* */
	unsigned long flags;

	/* Reference of WLAN */
	struct ac_wlan* wlan;
	struct capwap_list_item* wlanitem;

	/* Reference of Session */
	struct ac_session_t* session;

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

/* Management WLANS */
void ac_wlans_init(struct ac_session_t* session);
void ac_wlans_destroy(struct ac_session_t* session);

/* */
struct ac_wlan* ac_wlans_create_bssid(struct ac_device* device, uint8_t wlanid, const uint8_t* bssid, struct capwap_80211_addwlan_element* addwlan);
int ac_wlans_assign_bssid(struct ac_session_t* session, struct ac_wlan* wlan);
struct ac_wlan* ac_wlans_get_bssid(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid);
struct ac_wlan* ac_wlans_get_bssid_with_wlanid(struct ac_session_t* session, uint8_t radioid, uint8_t wlanid);
void ac_wlans_delete_bssid(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid);
void ac_wlans_free_bssid(struct ac_wlan* wlan);

/* Management Stations */
struct ac_station* ac_stations_create_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address);
struct ac_station* ac_stations_get_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address);
void ac_stations_delete_station(struct ac_session_t* session, struct ac_station* station);
void ac_stations_authorize_station(struct ac_session_t* session, struct ac_station* station);
void ac_stations_deauthorize_station(struct ac_session_t* session, struct ac_station* station);

/* */
void ac_stations_timeout(struct capwap_timeout* timeout, unsigned long index, void* context, void* param);

#endif /* __AC_WLANS_HEADER__ */
