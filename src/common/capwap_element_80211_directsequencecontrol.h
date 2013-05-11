#ifndef __CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_HEADER__
#define __CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_HEADER__

#define CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL			1028

struct capwap_80211_directsequencecontrol_element {
	unsigned char radioid;
	unsigned char currentchannel;
	unsigned char currentcca;
	unsigned long enerydetectthreshold;
};

#define CAPWAP_DSCONTROL_CCA_EDONLY				1
#define CAPWAP_DSCONTROL_CCA_CSONLY				2
#define CAPWAP_DSCONTROL_CCA_EDANDCS			4
#define CAPWAP_DSCONTROL_CCA_CSWITHTIME			8
#define CAPWAP_DSCONTROL_CCA_HRCSANDED			16

struct capwap_message_element* capwap_80211_dscontrol_element_create(void* data, unsigned long length);
int capwap_80211_dscontrol_element_validate(struct capwap_message_element* element);
void* capwap_80211_dscontrol_element_parsing(struct capwap_message_element* element);
void capwap_80211_dscontrol_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_DIRECTSEQUENCECONTROL_ELEMENT(x)		({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL);	\
																		f->create(x, sizeof(struct capwap_80211_directsequencecontrol_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_HEADER__ */
