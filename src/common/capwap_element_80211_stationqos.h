#ifndef __CAPWAP_ELEMENT_80211_STATION_QOS_PROFILE_HEADER__
#define __CAPWAP_ELEMENT_80211_STATION_QOS_PROFILE_HEADER__

#define CAPWAP_ELEMENT_80211_STATION_QOS_PROFILE		1037

struct capwap_80211_stationqos_element {
	uint8_t address[MACADDRESS_EUI48_LENGTH];
	uint8_t priority;
};

extern const struct capwap_message_elements_ops capwap_element_80211_stationqos_ops;

#endif /* __CAPWAP_ELEMENT_80211_STATION_QOS_PROFILE_HEADER__ */
