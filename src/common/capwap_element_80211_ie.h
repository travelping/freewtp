#ifndef __CAPWAP_ELEMENT_80211_IE_HEADER__
#define __CAPWAP_ELEMENT_80211_IE_HEADER__

#define CAPWAP_ELEMENT_80211_IE_VENDOR				0
#define CAPWAP_ELEMENT_80211_IE_TYPE				1029
#define CAPWAP_ELEMENT_80211_IE					(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_80211_IE_VENDOR, .type = CAPWAP_ELEMENT_80211_IE_TYPE }


#define CAPWAP_IE_BEACONS_ASSOCIATED				0x80
#define CAPWAP_IE_PROBE_RESPONSE_ASSOCIATED			0x40

struct capwap_80211_ie_element {
	uint8_t radioid;
	uint8_t wlanid;
	uint8_t flags;
	uint16_t ielength;
	uint8_t* ie;
};

extern const struct capwap_message_elements_ops capwap_element_80211_ie_ops;

#endif /* __CAPWAP_ELEMENT_80211_IE_HEADER__ */
