#ifndef __CAPWAP_ELEMENT_80211_TXPOWERLEVEL_HEADER__
#define __CAPWAP_ELEMENT_80211_TXPOWERLEVEL_HEADER__

#define CAPWAP_ELEMENT_80211_TXPOWERLEVEL				1042

#define CAPWAP_TXPOWERLEVEL_MAXLENGTH					8

struct capwap_80211_txpowerlevel_element {
	uint8_t radioid;
	uint8_t numlevels;
	uint16_t powerlevel[CAPWAP_TXPOWERLEVEL_MAXLENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_txpowerlevel_ops;

#endif /* __CAPWAP_ELEMENT_80211_TXPOWERLEVEL_HEADER__ */
