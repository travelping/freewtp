#ifndef __CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_HEADER__
#define __CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_HEADER__

#define CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES			1031

struct capwap_80211_miccountermeasures_element {
	uint8_t radioid;
	uint8_t wlanid;
	uint8_t address[MACADDRESS_EUI48_LENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_miccountermeasures_ops;

#endif /* __CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_HEADER__ */
