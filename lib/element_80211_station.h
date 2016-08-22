#ifndef __CAPWAP_ELEMENT_80211_STATION_HEADER__
#define __CAPWAP_ELEMENT_80211_STATION_HEADER__

#define CAPWAP_ELEMENT_80211_STATION_VENDOR		0
#define CAPWAP_ELEMENT_80211_STATION_TYPE		1036
#define CAPWAP_ELEMENT_80211_STATION			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_STATION_VENDOR, .type = CAPWAP_ELEMENT_80211_STATION_TYPE }


#define CAPWAP_STATION_RATES_MAXLENGTH			128

struct capwap_80211_station_element {
	uint8_t radioid;
	uint16_t associationid;
	uint8_t flags;
	uint8_t address[MACADDRESS_EUI48_LENGTH];
	uint16_t capabilities;
	uint8_t wlanid;
	uint8_t supportedratescount;
	uint8_t supportedrates[CAPWAP_STATION_RATES_MAXLENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_station_ops;

#endif /* __CAPWAP_ELEMENT_80211_STATION_HEADER__ */
