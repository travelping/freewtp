#ifndef __CAPWAP_ELEMENT_80211_MAC_PROFILE_HEADER__
#define __CAPWAP_ELEMENT_80211_MAC_PROFILE_HEADER__

#define CAPWAP_ELEMENT_80211_MAC_PROFILE_VENDOR		0
#define CAPWAP_ELEMENT_80211_MAC_PROFILE_TYPE		1061
#define CAPWAP_ELEMENT_80211_MAC_PROFILE				\
	(struct capwap_message_element_id) {				\
		.vendor = CAPWAP_ELEMENT_80211_MAC_PROFILE_VENDOR,	\
		.type = CAPWAP_ELEMENT_80211_MAC_PROFILE_TYPE		\
	}

struct capwap_80211_mac_profile_element {
	uint8_t mac_profile;
};

extern const struct capwap_message_elements_ops capwap_element_80211_mac_profile_ops;

#endif /* __CAPWAP_ELEMENT_80211_MAC_PROFILE_HEADER__ */
