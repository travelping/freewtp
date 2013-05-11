#ifndef __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__
#define __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__

#define CAPWAP_ELEMENT_80211_TXPOWER				1041

struct capwap_80211_txpower_element {
	unsigned char radioid;
	unsigned short currenttxpower;
};

struct capwap_message_element* capwap_80211_txpower_element_create(void* data, unsigned long length);
int capwap_80211_txpower_element_validate(struct capwap_message_element* element);
void* capwap_80211_txpower_element_parsing(struct capwap_message_element* element);
void capwap_80211_txpower_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_TXPOWER_ELEMENT(x)						({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_TXPOWER);	\
																		f->create(x, sizeof(struct capwap_80211_txpower_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_TXPOWER_HEADER__ */
