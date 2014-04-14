#ifndef __CAPWAP_ELEMENT_80211_WTP_RADIO_CONF_HEADER__
#define __CAPWAP_ELEMENT_80211_WTP_RADIO_CONF_HEADER__

#define CAPWAP_ELEMENT_80211_WTP_RADIO_CONF					1046

#define CAPWAP_WTP_RADIO_CONF_COUNTRY_LENGTH				4

#define CAPWAP_WTP_RADIO_CONF_SHORTPREAMBLE_DISABLE			0
#define CAPWAP_WTP_RADIO_CONF_SHORTPREAMBLE_ENABLE			1

struct capwap_80211_wtpradioconf_element {
	uint8_t radioid;
	uint8_t shortpreamble;
	uint8_t maxbssid;
	uint8_t dtimperiod;
	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
	uint16_t beaconperiod;
	uint8_t country[CAPWAP_WTP_RADIO_CONF_COUNTRY_LENGTH];
};

extern struct capwap_message_elements_ops capwap_element_80211_wtpradioconf_ops;

#endif /* __CAPWAP_ELEMENT_80211_WTP_RADIO_CONF_HEADER__ */
