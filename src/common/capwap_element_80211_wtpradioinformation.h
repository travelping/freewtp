#ifndef __CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_HEADER__
#define __CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_HEADER__

#define CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION			1048

struct capwap_80211_wtpradioinformation_element {
	unsigned char radioid;
	unsigned long radiotype;
};

#define CAPWAP_RADIO_TYPE_80211N			0x08
#define CAPWAP_RADIO_TYPE_80211G			0x04
#define CAPWAP_RADIO_TYPE_80211A			0x02
#define CAPWAP_RADIO_TYPE_80211B			0x01

struct capwap_message_element* capwap_80211_wtpradioinformation_element_create(void* data, unsigned long length);
int capwap_80211_wtpradioinformation_element_validate(struct capwap_message_element* element);
void* capwap_80211_wtpradioinformation_element_parsing(struct capwap_message_element* element);
void capwap_80211_wtpradioinformation_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_WTPRADIOINFORMATION_ELEMENT(x)			({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION);	\
																		f->create(x, sizeof(struct capwap_80211_wtpradioinformation_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_WTPRADIOINFORMATION_HEADER__ */
