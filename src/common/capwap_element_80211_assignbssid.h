#ifndef __CAPWAP_ELEMENT_80211_ASSIGN_BSSID_HEADER__
#define __CAPWAP_ELEMENT_80211_ASSIGN_BSSID_HEADER__

#define CAPWAP_ELEMENT_80211_ASSIGN_BSSID_VENDOR		0
#define CAPWAP_ELEMENT_80211_ASSIGN_BSSID_TYPE		1026
#define CAPWAP_ELEMENT_80211_ASSIGN_BSSID			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_ASSIGN_BSSID_VENDOR, .type = CAPWAP_ELEMENT_80211_ASSIGN_BSSID_TYPE }


struct capwap_80211_assignbssid_element {
	uint8_t radioid;
	uint8_t wlanid;
	uint8_t bssid[MACADDRESS_EUI48_LENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_assignbssid_ops;

#endif /* __CAPWAP_ELEMENT_80211_ASSIGN_BSSID_HEADER__ */
