#ifndef __CAPWAP_ELEMENT_80211N_STATION_INFO_HEADER__
#define __CAPWAP_ELEMENT_80211N_STATION_INFO_HEADER__

#define CAPWAP_ELEMENT_80211N_STATION_INFO_VENDOR				CAPWAP_VENDOR_TRAVELPING_ID
#define CAPWAP_ELEMENT_80211N_STATION_INFO_TYPE					17
#define CAPWAP_ELEMENT_80211N_STATION_INFO					(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211N_STATION_INFO_VENDOR, .type = CAPWAP_ELEMENT_80211N_STATION_INFO_TYPE }


#define CAPWAP_80211N_STATION_INFO_40MHZ_BANDWITH				(1 << 7)
#define CAPWAP_80211N_STATION_INFO_POWER_SAVE_MODE				((1 << 6) | (1 << 5))
#define CAPWAP_80211N_STATION_INFO_POWER_SAVE_MODE_SHIFT			5
#define CAPWAP_80211N_STATION_INFO_SHORT_GUARD_INTERVAL_AT_20MHZ		(1 << 4)
#define CAPWAP_80211N_STATION_INFO_SHORT_GUARD_INTERVAL_AT_40MHZ		(1 << 3)
#define CAPWAP_80211N_STATION_INFO_BLOCK_ACK_DELAY_MODE				(1 << 2)
#define CAPWAP_80211N_STATION_INFO_MAX_AMSDU_LENGTH_7935			(1 << 1)

#define MCS_SET_LENGTH		10

struct capwap_80211n_station_info_element {
	uint8_t address[MACADDRESS_EUI48_LENGTH];
        uint8_t flags;
	uint8_t maxrxfactor;
	uint8_t minstaspaceing;
	uint16_t hisuppdatarate;
	uint16_t ampdubufsize;
	uint8_t htcsupp;
	uint8_t mcsset[MCS_SET_LENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211n_station_info_ops;

#endif /* __CAPWAP_ELEMENT_80211N_STATION_INFO_HEADER__ */
