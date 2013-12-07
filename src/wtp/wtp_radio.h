#ifndef __WTP_RADIO_HEADER__
#define __WTP_RADIO_HEADER__

#define WTP_RADIO_ENABLED			0
#define WTP_RADIO_DISABLED			1
#define WTP_RADIO_HWFAILURE			2
#define WTP_RADIO_SWFAILURE			3

struct wtp_radio {
	int radioid;
	char device[IFNAMSIZ];

	int status;
	struct capwap_80211_antenna_element antenna;
	struct capwap_80211_directsequencecontrol_element directsequencecontrol;
	struct capwap_80211_macoperation_element macoperation;
	struct capwap_80211_multidomaincapability_element multidomaincapability;
	struct capwap_80211_ofdmcontrol_element ofdmcontrol;
	struct capwap_80211_supportedrates_element supportedrates;
	struct capwap_80211_txpower_element txpower;
	struct capwap_80211_txpowerlevel_element txpowerlevel;
	struct capwap_80211_wtpradioconf_element radioconfig;
	struct capwap_80211_wtpradioinformation_element radioinformation;
};

/* */
uint32_t wtp_radio_create_wlan(struct capwap_parsed_packet* packet, struct capwap_80211_assignbssid_element* bssid);
uint32_t wtp_radio_update_wlan(struct capwap_parsed_packet* packet);
uint32_t wtp_radio_delete_wlan(struct capwap_parsed_packet* packet);

#endif /* __WTP_RADIO_HEADER__ */
