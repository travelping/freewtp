#ifndef __CAPWAP_ELEMENT_80211_SUPPORTEDRATES_HEADER__
#define __CAPWAP_ELEMENT_80211_SUPPORTEDRATES_HEADER__

#define CAPWAP_ELEMENT_80211_SUPPORTEDRATES		1040

#define CAPWAP_SUPPORTEDRATES_MINLENGTH			2
#define CAPWAP_SUPPORTEDRATES_MAXLENGTH			8

struct capwap_80211_supportedrates_element {
	unsigned char radioid;
	unsigned char supportedratescount;
	unsigned char supportedrates[CAPWAP_SUPPORTEDRATES_MAXLENGTH];
};

struct capwap_message_element* capwap_80211_supportedrates_element_create(void* data, unsigned long length);
int capwap_80211_supportedrates_element_validate(struct capwap_message_element* element);
void* capwap_80211_supportedrates_element_parsing(struct capwap_message_element* element);
void capwap_80211_supportedrates_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_SUPPORTEDRATES_ELEMENT(x)				({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_SUPPORTEDRATES);	\
																		f->create(x, sizeof(struct capwap_80211_supportedrates_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_SUPPORTEDRATES_HEADER__ */
