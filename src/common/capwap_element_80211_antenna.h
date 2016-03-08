#ifndef __CAPWAP_ELEMENT_80211_ANTENNA_HEADER__
#define __CAPWAP_ELEMENT_80211_ANTENNA_HEADER__

#define CAPWAP_ELEMENT_80211_ANTENNA_VENDOR			0
#define CAPWAP_ELEMENT_80211_ANTENNA_TYPE			1025
#define CAPWAP_ELEMENT_80211_ANTENNA				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_ANTENNA_VENDOR, .type = CAPWAP_ELEMENT_80211_ANTENNA_TYPE }


#define CAPWAP_ANTENNA_DIVERSITY_DISABLE		0
#define CAPWAP_ANTENNA_DIVERSITY_ENABLE			1

#define CAPWAP_ANTENNA_COMBINER_SECT_LEFT		1
#define CAPWAP_ANTENNA_COMBINER_SECT_RIGHT		2
#define CAPWAP_ANTENNA_COMBINER_SECT_OMNI		3
#define CAPWAP_ANTENNA_COMBINER_SECT_MIMO		4

#define CAPWAP_ANTENNA_INTERNAL					1
#define CAPWAP_ANTENNA_EXTERNAL					2

#define CAPWAP_ANTENNASELECTIONS_MAXLENGTH		255

struct capwap_80211_antenna_element {
	uint8_t radioid;
	uint8_t diversity;
	uint8_t combiner;
	struct capwap_array* selections;
};

extern const struct capwap_message_elements_ops capwap_element_80211_antenna_ops;
void capwap_element_80211_antenna_copy(struct capwap_80211_antenna_element* dst, struct capwap_80211_antenna_element* src);

#endif /* __CAPWAP_ELEMENT_80211_ANTENNA_HEADER__ */
