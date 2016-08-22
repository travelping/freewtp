#ifndef __CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_HEADER__
#define __CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_HEADER__

#define CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_VENDOR			0
#define CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_TYPE			1032
#define CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_VENDOR, .type = CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_TYPE }


struct capwap_80211_multidomaincapability_element {
	uint8_t radioid;
	uint16_t firstchannel;
	uint16_t numberchannels;
	uint16_t maxtxpowerlevel;
};

extern const struct capwap_message_elements_ops capwap_element_80211_multidomaincapability_ops;

#endif /* __CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_HEADER__ */
