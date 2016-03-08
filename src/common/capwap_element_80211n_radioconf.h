#ifndef __CAPWAP_ELEMENT_80211N_RADIO_CONF_HEADER__
#define __CAPWAP_ELEMENT_80211N_RADIO_CONF_HEADER__

#define CAPWAP_ELEMENT_80211N_RADIO_CONF_VENDOR					CAPWAP_VENDOR_TRAVELPING_ID
#define CAPWAP_ELEMENT_80211N_RADIO_CONF_TYPE					8
#define CAPWAP_ELEMENT_80211N_RADIO_CONF					(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211N_RADIO_CONF_VENDOR, .type = CAPWAP_ELEMENT_80211N_RADIO_CONF_TYPE }


#define CAPWAP_80211N_RADIO_CONF_A_MSDU			(1 << 7)
#define CAPWAP_80211N_RADIO_CONF_A_MPDU			(1 << 6)
#define CAPWAP_80211N_RADIO_CONF_11N_ONLY		(1 << 5)
#define CAPWAP_80211N_RADIO_CONF_SHORT_GUARD_INTERVAL	(1 << 4)
#define CAPWAP_80211N_RADIO_CONF_20MHZ_BANDWITH		(1 << 3)

#define CAPWAP_80211N_RADIO_CONF_MASK			0xF8

struct capwap_80211n_radioconf_element {
	uint8_t radioid;
	uint8_t flags;
	uint8_t maxsupmcs;
	uint8_t maxmandmcs;
	uint8_t txant;
	uint8_t rxant;
};

extern const struct capwap_message_elements_ops capwap_element_80211n_radioconf_ops;

#endif /* __CAPWAP_ELEMENT_80211N_RADIO_CONF_HEADER__ */
