#ifndef __CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_HEADER__
#define __CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_HEADER__

#define CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL			1028

#define CAPWAP_DSCONTROL_CCA_EDONLY				1
#define CAPWAP_DSCONTROL_CCA_CSONLY				2
#define CAPWAP_DSCONTROL_CCA_EDANDCS			4
#define CAPWAP_DSCONTROL_CCA_CSWITHTIME			8
#define CAPWAP_DSCONTROL_CCA_HRCSANDED			16
#define CAPWAP_DSCONTROL_CCA_MASK				0x1f

struct capwap_80211_directsequencecontrol_element {
	uint8_t radioid;
	uint8_t currentchannel;
	uint8_t currentcca;
	uint32_t enerydetectthreshold;
};

extern const struct capwap_message_elements_ops capwap_element_80211_directsequencecontrol_ops;

#endif /* __CAPWAP_ELEMENT_80211_DIRECTSEQUENCECONTROL_HEADER__ */
