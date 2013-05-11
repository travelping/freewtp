#ifndef __CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_HEADER__
#define __CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_HEADER__

#define CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY			1032

struct capwap_80211_multidomaincapability_element {
	unsigned char radioid;
	unsigned short firstchannel;
	unsigned short numberchannels;
	unsigned short maxtxpowerlevel;
};

struct capwap_message_element* capwap_80211_multidomaincapability_element_create(void* data, unsigned long length);
int capwap_80211_multidomaincapability_element_validate(struct capwap_message_element* element);
void* capwap_80211_multidomaincapability_element_parsing(struct capwap_message_element* element);
void capwap_80211_multidomaincapability_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_MULTIDOMAINCAPABILITY_ELEMENT(x)		({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY);	\
																		f->create(x, sizeof(struct capwap_80211_multidomaincapability_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_MULTIDOMAINCAPABILITY_HEADER__ */
