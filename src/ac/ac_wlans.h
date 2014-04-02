#ifndef __AC_WLANS_HEADER__
#define __AC_WLANS_HEADER__

/* AC WLAN */
struct ac_wlan {
	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
	uint8_t wlanid;

	/* CAPWAP Session */
	struct ac_session_t* session;
	struct ac_session_data_t* sessiondata;

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

	/* Local cache stations */
	struct capwap_list* stations;
};

/* AC Station */
struct ac_station {
	uint8_t address[MACADDRESS_EUI48_LENGTH];

	/* Reference of WLAN */
	struct ac_wlan_device* wlan;
	struct capwap_list_item* itemlist;
};

/* */
struct ac_wlans {
	struct capwap_list* wlans[RADIOID_MAX_COUNT];
};

/* */
struct ac_wlans* ac_wlans_init(void);
void ac_wlans_destroy(struct ac_wlans* wlans);

/* */
struct ac_wlan* ac_wlans_create_bssid(struct ac_wlans* wlans, uint8_t radioid, uint8_t wlanid, uint8_t* bssid);
struct ac_wlan* ac_wlans_get_bssid(struct ac_wlans* wlans, uint8_t radioid, uint8_t* bssid);
struct ac_wlan* ac_wlans_get_bssid_with_wlanid(struct ac_wlans* wlans, uint8_t radioid, uint8_t wlanid);
void ac_wlans_delete_bssid(struct ac_wlans* wlans, uint8_t radioid, uint8_t* bssid);

/* */
void ac_wlans_set_bssid_capability(struct ac_wlan* wlan, struct capwap_80211_addwlan_element* addwlan);

#endif /* __AC_WLANS_HEADER__ */
