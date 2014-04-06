#ifndef __AC_WLANS_HEADER__
#define __AC_WLANS_HEADER__

#include "ieee80211.h"

/* */
#define AC_WLANS_STATIONS_HASH_SIZE		256
#define AC_WLANS_STATIONS_KEY_SIZE		MACADDRESS_EUI48_LENGTH

/* AC WLAN */
struct ac_wlan {
	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
	uint8_t radioid;
	uint8_t wlanid;

	/* CAPWAP Session */
	struct ac_session_t* session;
	struct ac_session_data_t* sessiondata;

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
	uint8_t* ssid;
};

/* AC Station */
struct ac_station {
	uint8_t address[MACADDRESS_EUI48_LENGTH];

	/* Reference of WLAN */
	struct ac_wlan* wlan;
	struct capwap_list_item* wlanitem;
};

/* */
struct ac_wlans {
	struct capwap_list* wlans[RADIOID_MAX_COUNT];

	/* Stations */
	struct capwap_hash* stations;
};

/* Management WLANS */
void ac_wlans_init(struct ac_session_t* session);
void ac_wlans_destroy(struct ac_session_t* session);

/* */
struct ac_wlan* ac_wlans_create_bssid(struct ac_session_t* session, uint8_t radioid, uint8_t wlanid, const uint8_t* bssid);
struct ac_wlan* ac_wlans_get_bssid(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid);
struct ac_wlan* ac_wlans_get_bssid_with_wlanid(struct ac_session_t* session, uint8_t radioid, uint8_t wlanid);
void ac_wlans_delete_bssid(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid);

/* */
void ac_wlans_set_bssid_capability(struct ac_wlan* wlan, struct capwap_80211_addwlan_element* addwlan);

/* Management Stations */
struct ac_station* ac_stations_create_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address);
struct ac_station* ac_stations_get_station(struct ac_session_t* session, uint8_t radioid, const uint8_t* bssid, const uint8_t* address);
void ac_stations_delete_station(struct ac_session_t* session, const uint8_t* address);

#endif /* __AC_WLANS_HEADER__ */
