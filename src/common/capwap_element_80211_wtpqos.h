#ifndef __CAPWAP_ELEMENT_80211_WTP_QOS_HEADER__
#define __CAPWAP_ELEMENT_80211_WTP_QOS_HEADER__

#define CAPWAP_ELEMENT_80211_WTP_QOS				1045

#define CAPWAP_WTP_QOS_SUBELEMENT_VOICE				0
#define CAPWAP_WTP_QOS_SUBELEMENT_VIDEO				1
#define CAPWAP_WTP_QOS_SUBELEMENT_BESTEFFORT		2
#define CAPWAP_WTP_QOS_SUBELEMENT_BACKGROUND		3
#define CAPWAP_WTP_QOS_SUBELEMENTS					4

#define CAPWAP_WTP_QOS_POLICY_MASK					0x1f

#define CAPWAP_WTP_QOS_PRIORIY_MASK					0x07
#define CAPWAP_WTP_QOS_DSCP_MASK					0x3f

struct capwap_80211_wtpqos_subelement {
	uint8_t queuedepth;
	uint16_t cwmin;
	uint16_t cwmax;
	uint8_t aifs;
	uint8_t priority8021p;
	uint8_t dscp;
};

struct capwap_80211_wtpqos_element {
	uint8_t radioid;
	uint8_t taggingpolicy;
	struct capwap_80211_wtpqos_subelement qos[CAPWAP_WTP_QOS_SUBELEMENTS];
};

extern struct capwap_message_elements_ops capwap_element_80211_wtpqos_ops;

#endif /* __CAPWAP_ELEMENT_80211_WTP_QOS_HEADER__ */
