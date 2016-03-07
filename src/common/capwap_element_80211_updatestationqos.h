#ifndef __CAPWAP_ELEMENT_80211_UPDATE_STATION_QOS_HEADER__
#define __CAPWAP_ELEMENT_80211_UPDATE_STATION_QOS_HEADER__

#define CAPWAP_ELEMENT_80211_UPDATE_STATION_QOS		1043

#define CAPWAP_UPDATE_STATION_QOS_SUBELEMENTS				4

#define CAPWAP_UPDATE_STATION_QOS_PRIORIY_MASK				0x07
#define CAPWAP_UPDATE_STATION_QOS_DSCP_MASK					0x3f

struct capwap_80211_updatestationqos_subelement {
	uint8_t priority8021p;
	uint8_t dscp;
};

struct capwap_80211_updatestationqos_element {
	uint8_t radioid;
	uint8_t address[MACADDRESS_EUI48_LENGTH];
	struct capwap_80211_updatestationqos_subelement qos[CAPWAP_UPDATE_STATION_QOS_SUBELEMENTS];
};

extern const struct capwap_message_elements_ops capwap_element_80211_updatestationqos_ops;

#endif /* __CAPWAP_ELEMENT_80211_UPDATE_STATION_QOS_HEADER__ */
