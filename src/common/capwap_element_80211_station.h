#ifndef __CAPWAP_ELEMENT_80211_STATION_HEADER__
#define __CAPWAP_ELEMENT_80211_STATION_HEADER__

#define CAPWAP_ELEMENT_80211_STATION		1036

#define CAPWAP_STATION_ADDRESS_LENGTH			6
#define CAPWAP_STATION_RATES_MAXLENGTH			128

struct capwap_80211_station_element {
	uint8_t radioid;
	uint16_t associationid;
	uint8_t flags;
	uint8_t address[CAPWAP_STATION_ADDRESS_LENGTH];
	uint16_t capabilities;
	uint8_t wlanid;
	uint8_t supportedratescount;
	uint8_t supportedrates[CAPWAP_STATION_RATES_MAXLENGTH];
};

extern struct capwap_message_elements_ops capwap_element_80211_station_ops;

#endif /* __CAPWAP_ELEMENT_80211_STATION_HEADER__ */
