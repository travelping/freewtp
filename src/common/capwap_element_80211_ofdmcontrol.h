#ifndef __CAPWAP_ELEMENT_80211_OFDMCONTROL_HEADER__
#define __CAPWAP_ELEMENT_80211_OFDMCONTROL_HEADER__

#define CAPWAP_ELEMENT_80211_OFDMCONTROL			1033

#define CAPWAP_OFDMCONTROL_BAND_515_525				0x01
#define CAPWAP_OFDMCONTROL_BAND_525_535				0x02
#define CAPWAP_OFDMCONTROL_BAND_5725_5825			0x04
#define CAPWAP_OFDMCONTROL_BAND_547_5725			0x08
#define CAPWAP_OFDMCONTROL_BAND_JP_525				0x10
#define CAPWAP_OFDMCONTROL_BAND_503_5091			0x20
#define CAPWAP_OFDMCONTROL_BAND_494_499				0x40

struct capwap_80211_ofdmcontrol_element {
	uint8_t radioid;
	uint8_t currentchannel;
	uint8_t bandsupport;
	uint32_t tithreshold;
};

extern struct capwap_message_elements_ops capwap_element_80211_ofdmcontrol_ops;

#endif /* __CAPWAP_ELEMENT_80211_OFDMCONTROL_HEADER__ */
