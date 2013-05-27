#ifndef __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__
#define __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__

#define CAPWAP_ELEMENT_80211_MACOPERATION			1030

struct capwap_80211_macoperation_element {
	uint8_t radioid;
	uint16_t rtsthreshold;
	uint8_t shortretry;
	uint8_t longretry;
	uint16_t fragthreshold;
	uint32_t txmsdulifetime;
	uint32_t rxmsdulifetime;
};

extern struct capwap_message_elements_ops capwap_element_80211_macoperation_ops;

#endif /* __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__ */
