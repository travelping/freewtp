#ifndef __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__
#define __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__

#define CAPWAP_ELEMENT_80211_MACOPERATION_VENDOR			0
#define CAPWAP_ELEMENT_80211_MACOPERATION_TYPE			1030
#define CAPWAP_ELEMENT_80211_MACOPERATION				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_MACOPERATION_VENDOR, .type = CAPWAP_ELEMENT_80211_MACOPERATION_TYPE }


struct capwap_80211_macoperation_element {
	uint8_t radioid;
	uint16_t rtsthreshold;
	uint8_t shortretry;
	uint8_t longretry;
	uint16_t fragthreshold;
	uint32_t txmsdulifetime;
	uint32_t rxmsdulifetime;
};

extern const struct capwap_message_elements_ops capwap_element_80211_macoperation_ops;

#endif /* __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__ */
