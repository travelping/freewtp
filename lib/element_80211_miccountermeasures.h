#ifndef __CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_HEADER__
#define __CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_HEADER__

#define CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_VENDOR			0
#define CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_TYPE			1031
#define CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_VENDOR, .type = CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_TYPE }


struct capwap_80211_miccountermeasures_element {
	uint8_t radioid;
	uint8_t wlanid;
	uint8_t address[MACADDRESS_EUI48_LENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_miccountermeasures_ops;

#endif /* __CAPWAP_ELEMENT_80211_MIC_COUNTERMEASURES_HEADER__ */
