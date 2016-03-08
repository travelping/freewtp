#ifndef __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__
#define __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__

#define CAPWAP_ELEMENT_80211_TXPOWER_VENDOR				0
#define CAPWAP_ELEMENT_80211_TXPOWER_TYPE				1041
#define CAPWAP_ELEMENT_80211_TXPOWER					(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_TXPOWER_VENDOR, .type = CAPWAP_ELEMENT_80211_TXPOWER_TYPE }


struct capwap_80211_txpower_element {
	uint8_t radioid;
	uint16_t currenttxpower;
};

extern const struct capwap_message_elements_ops capwap_element_80211_txpower_ops;

#endif /* __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__ */
