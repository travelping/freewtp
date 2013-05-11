#ifndef __CAPWAP_ELEMENT_80211_RATESET_HEADER__
#define __CAPWAP_ELEMENT_80211_RATESET_HEADER__

#define CAPWAP_ELEMENT_80211_RATESET		1034

#define CAPWAP_RATESET_MINLENGTH			2
#define CAPWAP_RATESET_MAXLENGTH			8

struct capwap_80211_rateset_element {
	unsigned char radioid;
	unsigned char ratesetcount;
	unsigned char rateset[CAPWAP_RATESET_MAXLENGTH];
};

struct capwap_message_element* capwap_80211_rateset_element_create(void* data, unsigned long length);
int capwap_80211_rateset_element_validate(struct capwap_message_element* element);
void* capwap_80211_rateset_element_parsing(struct capwap_message_element* element);
void capwap_80211_rateset_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_RATESET_ELEMENT(x)						({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_RATESET);	\
																		f->create(x, sizeof(struct capwap_80211_rateset_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_RATESET_HEADER__ */
