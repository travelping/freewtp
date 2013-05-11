#ifndef __CAPWAP_ELEMENT_80211_ANTENNA_HEADER__
#define __CAPWAP_ELEMENT_80211_ANTENNA_HEADER__

#define CAPWAP_ELEMENT_80211_ANTENNA			1025

#define CAPWAP_ANTENNASELECTIONS_MAXLENGTH		255

struct capwap_80211_antenna_element {
	unsigned char radioid;
	unsigned char diversity;
	unsigned char combiner;
	unsigned char antennacount;
	unsigned char antennaselections[CAPWAP_ANTENNASELECTIONS_MAXLENGTH];
};

#define CAPWAP_ANTENNA_DIVERSITY_DISABLE		0
#define CAPWAP_ANTENNA_DIVERSITY_ENABLE			1

#define CAPWAP_ANTENNA_COMBINER_SECT_LEFT		1
#define CAPWAP_ANTENNA_COMBINER_SECT_RIGHT		2
#define CAPWAP_ANTENNA_COMBINER_SECT_OMNI		3
#define CAPWAP_ANTENNA_COMBINER_SECT_MIMO		4

#define CAPWAP_ANTENNA_INTERNAL					1
#define CAPWAP_ANTENNA_EXTERNAL					2

struct capwap_message_element* capwap_80211_antenna_element_create(void* data, unsigned long length);
int capwap_80211_antenna_element_validate(struct capwap_message_element* element);
void* capwap_80211_antenna_element_parsing(struct capwap_message_element* element);
void capwap_80211_antenna_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_ANTENNA_ELEMENT(x)						({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_ANTENNA);	\
																		f->create(x, sizeof(struct capwap_80211_antenna_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_ANTENNA_HEADER__ */
