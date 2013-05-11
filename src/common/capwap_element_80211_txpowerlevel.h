#ifndef __CAPWAP_ELEMENT_80211_TXPOWERLEVEL_HEADER__
#define __CAPWAP_ELEMENT_80211_TXPOWERLEVEL_HEADER__

#define CAPWAP_ELEMENT_80211_TXPOWERLEVEL				1042

#define CAPWAP_TXPOWERLEVEL_MAXLENGTH					8

struct capwap_80211_txpowerlevel_element {
	unsigned char radioid;
	unsigned char numlevels;
	unsigned short powerlevel[CAPWAP_TXPOWERLEVEL_MAXLENGTH];
};

struct capwap_message_element* capwap_80211_txpowerlevel_element_create(void* data, unsigned long length);
int capwap_80211_txpowerlevel_element_validate(struct capwap_message_element* element);
void* capwap_80211_txpowerlevel_element_parsing(struct capwap_message_element* element);
void capwap_80211_txpowerlevel_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_TXPOWERLEVEL_ELEMENT(x)					({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_TXPOWERLEVEL);	\
																		f->create(x, sizeof(struct capwap_80211_txpowerlevel_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_TXPOWERLEVEL_HEADER__ */
