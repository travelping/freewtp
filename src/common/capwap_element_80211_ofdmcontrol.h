#ifndef __CAPWAP_ELEMENT_80211_OFDMCONTROL_HEADER__
#define __CAPWAP_ELEMENT_80211_OFDMCONTROL_HEADER__

#define CAPWAP_ELEMENT_80211_OFDMCONTROL			1033

struct capwap_80211_ofdmcontrol_element {
	unsigned char radioid;
	unsigned char currentchannel;
	unsigned char bandsupport;
	unsigned long tithreshold;
};

#define CAPWAP_OFDMCONTROL_BAND_515_525				0x01
#define CAPWAP_OFDMCONTROL_BAND_525_535				0x02
#define CAPWAP_OFDMCONTROL_BAND_5725_5825			0x04
#define CAPWAP_OFDMCONTROL_BAND_547_5725			0x08
#define CAPWAP_OFDMCONTROL_BAND_JP_525				0x10
#define CAPWAP_OFDMCONTROL_BAND_503_5091			0x20
#define CAPWAP_OFDMCONTROL_BAND_494_499				0x40

struct capwap_message_element* capwap_80211_ofdmcontrol_element_create(void* data, unsigned long length);
int capwap_80211_ofdmcontrol_element_validate(struct capwap_message_element* element);
void* capwap_80211_ofdmcontrol_element_parsing(struct capwap_message_element* element);
void capwap_80211_ofdmcontrol_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_OFDMCONTROL_ELEMENT(x)					({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_OFDMCONTROL);	\
																		f->create(x, sizeof(struct capwap_80211_ofdmcontrol_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_OFDMCONTROL_HEADER__ */
