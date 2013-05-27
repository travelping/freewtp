#ifndef __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__
#define __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__

#define CAPWAP_ELEMENT_80211_TXPOWER				1041

struct capwap_80211_txpower_element {
	uint8_t radioid;
	uint16_t currenttxpower;
};

extern struct capwap_message_elements_ops capwap_element_80211_txpower_ops;

#endif /* __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__ */
