#ifndef __WTP_RADIO_HEADER__
#define __WTP_RADIO_HEADER__

#include "ieee80211.h"

/* */
#define WTP_RADIO_ENABLED			0
#define WTP_RADIO_DISABLED			1
#define WTP_RADIO_HWFAILURE			2
#define WTP_RADIO_SWFAILURE			3

/* */
#define WTP_RADIO_ACL_HASH_SIZE		64

#define WTP_RADIO_ACL_STATION_ALLOW			0
#define WTP_RADIO_ACL_STATION_DENY			1

/* */
#define WTP_PREFIX_NAME_MAX_LENGTH			(IFNAMSIZ - 6)
#define WTP_PREFIX_DEFAULT_NAME				"ap"

struct wtp_radio_wlan {
	uint8_t wlanid;
	struct wifi_wlan* wlanhandle;
	struct wtp_radio* radio;
};

/* */
struct wtp_radio_wlanpool {
	struct wifi_wlan* wlanhandle;
	struct wtp_radio* radio;
};

struct capwap_80211_ie_element_ht_cap {
	struct capwap_80211_ie_element ie;
	struct ieee80211_ie_ht_cap ht_cap;
} STRUCT_PACKED;

/* */
struct wtp_radio {
	uint8_t radioid;
	char device[IFNAMSIZ];
	struct wifi_device* devicehandle;

	char wlanprefix[IFNAMSIZ];
	struct capwap_list* wlan;
	struct capwap_list* wlanpool;

	int status;
	struct capwap_80211_antenna_element antenna;
	struct capwap_80211_directsequencecontrol_element directsequencecontrol;
	struct capwap_80211_macoperation_element macoperation;
	struct capwap_80211_multidomaincapability_element multidomaincapability;
	struct capwap_80211_ofdmcontrol_element ofdmcontrol;
	struct capwap_80211_rateset_element rateset;
	struct capwap_80211_supportedrates_element supportedrates;
	struct capwap_80211_txpower_element txpower;
	struct capwap_80211_txpowerlevel_element txpowerlevel;
	struct capwap_80211_wtpradioconf_element radioconfig;
	struct capwap_80211n_radioconf_element n_radio_cfg;
	struct capwap_80211_wtpradioinformation_element radioinformation;
	struct capwap_80211_wtpqos_element qos;
	struct capwap_80211_ie_element_ht_cap ht_cap;
};

/* */
void wtp_radio_init(void);
void wtp_radio_close(void);
void wtp_radio_free(void);

/* */
struct wtp_radio* wtp_radio_create_phy(void);
struct wtp_radio* wtp_radio_get_phy(uint8_t radioid);
struct wtp_radio_wlan* wtp_radio_get_wlan(struct wtp_radio* radio, uint8_t wlanid);
struct wtp_radio_wlan* wtp_radio_search_wlan(struct wtp_radio* radio, const uint8_t* bssid);

/* */
void wtp_radio_receive_data_packet(uint8_t radioid, unsigned short binding, const uint8_t* frame, int length);

/* */
int wtp_radio_setconfiguration(struct capwap_parsed_packet* packet);

/* */
uint32_t wtp_radio_create_wlan(struct capwap_parsed_packet* packet, struct capwap_80211_assignbssid_element* bssid);
uint32_t wtp_radio_update_wlan(struct capwap_parsed_packet* packet);
uint32_t wtp_radio_delete_wlan(struct capwap_parsed_packet* packet);

/* */
uint32_t wtp_radio_add_station(struct capwap_parsed_packet* packet);
uint32_t wtp_radio_delete_station(struct capwap_parsed_packet* packet);

/* Station ACL */
int wtp_radio_acl_station(const uint8_t* macaddress);
void wtp_radio_acl_addstation(const uint8_t* macaddress);
void wtp_radio_acl_deletestation(const uint8_t* macaddress);

#endif /* __WTP_RADIO_HEADER__ */
