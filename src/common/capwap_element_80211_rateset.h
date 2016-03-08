#ifndef __CAPWAP_ELEMENT_80211_RATESET_HEADER__
#define __CAPWAP_ELEMENT_80211_RATESET_HEADER__

#define CAPWAP_ELEMENT_80211_RATESET_VENDOR		0
#define CAPWAP_ELEMENT_80211_RATESET_TYPE		1034
#define CAPWAP_ELEMENT_80211_RATESET			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_RATESET_VENDOR, .type = CAPWAP_ELEMENT_80211_RATESET_TYPE }


#define CAPWAP_RATESET_MINLENGTH			2
#define CAPWAP_RATESET_MAXLENGTH			8

struct capwap_80211_rateset_element {
	uint8_t radioid;
	uint8_t ratesetcount;
	uint8_t rateset[CAPWAP_RATESET_MAXLENGTH];
};

extern const struct capwap_message_elements_ops capwap_element_80211_rateset_ops;

#endif /* __CAPWAP_ELEMENT_80211_RATESET_HEADER__ */
