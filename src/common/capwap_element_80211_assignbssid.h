#ifndef __CAPWAP_ELEMENT_80211_ASSIGN_BSSID_HEADER__
#define __CAPWAP_ELEMENT_80211_ASSIGN_BSSID_HEADER__

#define CAPWAP_ELEMENT_80211_ASSIGN_BSSID		1026

struct capwap_80211_assignbssid_element {
	uint8_t radioid;
	uint8_t wlanid;
	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_assignbssid_ops;

#endif /* __CAPWAP_ELEMENT_80211_ASSIGN_BSSID_HEADER__ */
