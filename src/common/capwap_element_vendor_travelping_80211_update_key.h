#ifndef __CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY_HEADER__
#define __CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY_HEADER__

#define CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY_VENDOR	CAPWAP_VENDOR_TRAVELPING_ID
#define CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY_TYPE		19
#define CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY		\
	(struct capwap_message_element_id){				\
		.vendor = CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY_VENDOR,	\
		.type = CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY_TYPE		\
	}

#define CAPWAP_UPDATE_WLAN_KEY_STATUS_REKEYING		2
#define CAPWAP_UPDATE_WLAN_KEY_STATUS_COMPLETE		3

struct capwap_vendor_travelping_80211_update_key_element {
	uint8_t radioid;
	uint8_t wlanid;
	uint8_t keyindex;
	uint8_t keystatus;
	uint32_t ciphersuite;
	uint16_t keylength;
	uint8_t key[];
};

extern const struct capwap_message_elements_ops capwap_element_vendor_travelping_80211_update_key_ops;

#endif /* __CAPWAP_ELEMENT_VENDOR_TRAVELPING_80211_UPDATE_KEY_HEADER__ */
