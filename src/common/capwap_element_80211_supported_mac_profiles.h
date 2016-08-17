#ifndef __CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES_HEADER__
#define __CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES_HEADER__

#define CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES_VENDOR		0
#define CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES_TYPE		1060
#define CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES			\
	(struct capwap_message_element_id) {				\
		.vendor = CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES_VENDOR,	\
		.type = CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES_TYPE	\
	}


struct capwap_80211_supported_mac_profiles_element {
	uint8_t supported_mac_profilescount;
	uint8_t supported_mac_profiles[];
};

extern const struct capwap_message_elements_ops capwap_element_80211_supported_mac_profiles_ops;

#endif /* __CAPWAP_ELEMENT_80211_SUPPORTED_MAC_PROFILES_HEADER__ */
