#ifndef __CAPWAP_ELEMENT_80211_DELETE_WLAN_HEADER__
#define __CAPWAP_ELEMENT_80211_DELETE_WLAN_HEADER__

#define CAPWAP_ELEMENT_80211_DELETE_WLAN		1027

struct capwap_80211_deletewlan_element {
	uint8_t radioid;
	uint8_t wlanid;
};

extern const struct capwap_message_elements_ops capwap_element_80211_deletewlan_ops;

#endif /* __CAPWAP_ELEMENT_80211_DELETE_WLAN_HEADER__ */
