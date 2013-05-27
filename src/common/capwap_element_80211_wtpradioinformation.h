#ifndef __CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_HEADER__
#define __CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_HEADER__

#define CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION			1048

#define CAPWAP_RADIO_TYPE_80211B			0x01
#define CAPWAP_RADIO_TYPE_80211A			0x02
#define CAPWAP_RADIO_TYPE_80211G			0x04
#define CAPWAP_RADIO_TYPE_80211N			0x08

struct capwap_80211_wtpradioinformation_element {
	uint8_t radioid;
	uint32_t radiotype;
};

extern struct capwap_message_elements_ops capwap_element_80211_wtpradioinformation_ops;

#endif /* __CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_HEADER__ */
