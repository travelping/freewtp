#ifndef __WTP_RADIO_HEADER__
#define __WTP_RADIO_HEADER__

#include "ieee80211.h"

/* */
#define WTP_RADIO_ENABLED			0
#define WTP_RADIO_DISABLED			1
#define WTP_RADIO_HWFAILURE			2
#define WTP_RADIO_SWFAILURE			3

/* */
#define WTP_PREFIX_NAME_MAX_LENGTH			(IFNAMSIZ - 6)
#define WTP_PREFIX_DEFAULT_NAME				"ap"

#define WTP_RADIO_WLAN_STATE_IDLE			0
#define WTP_RADIO_WLAN_STATE_CREATED		1
#define WTP_RADIO_WLAN_STATE_READY			2
#define WTP_RADIO_WLAN_STATE_AP				3

struct wtp_radio_wlan {
	struct wtp_radio* radio;
	int state;

	uint8_t wlanid;
	char wlanname[IFNAMSIZ];
	uint8_t bssid[ETH_ALEN];

	/* */
	uint16_t capability;
	uint8_t qos;
	uint8_t authmode;
	uint8_t macmode;
	uint8_t tunnelmode;
	uint8_t ssid_hidden;
	char ssid[IEEE80211_IE_SSID_MAX_LENGTH + 1];
};

/* */
struct wtp_radio {
	uint8_t radioid;
	char device[IFNAMSIZ];

	struct capwap_array* wlan;

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
	struct capwap_80211_wtpradioinformation_element radioinformation;
	struct capwap_80211_wtpqos_element qos;
};

/* */
void wtp_radio_init(void);
void wtp_radio_close(void);
void wtp_radio_free(void);

/* */
struct wtp_radio* wtp_radio_create_phy(void);
struct wtp_radio* wtp_radio_get_phy(uint8_t radioid);
struct wtp_radio_wlan* wtp_radio_get_wlan(struct wtp_radio* radio, uint8_t wlanid);

/* */
int wtp_radio_setconfiguration(struct capwap_parsed_packet* packet);

/* */
uint32_t wtp_radio_create_wlan(struct capwap_parsed_packet* packet, struct capwap_80211_assignbssid_element* bssid);
uint32_t wtp_radio_update_wlan(struct capwap_parsed_packet* packet);
uint32_t wtp_radio_delete_wlan(struct capwap_parsed_packet* packet);

#endif /* __WTP_RADIO_HEADER__ */
