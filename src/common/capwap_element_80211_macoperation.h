#ifndef __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__
#define __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__

#define CAPWAP_ELEMENT_80211_MACOPERATION			1030

struct capwap_80211_macoperation_element {
	unsigned char radioid;
	unsigned short rtsthreshold;
	unsigned char shortretry;
	unsigned char longretry;
	unsigned short fragthreshold;
	unsigned long txmsdulifetime;
	unsigned long rxmsdulifetime;
};

struct capwap_message_element* capwap_80211_macoperation_element_create(void* data, unsigned long length);
int capwap_80211_macoperation_element_validate(struct capwap_message_element* element);
void* capwap_80211_macoperation_element_parsing(struct capwap_message_element* element);
void capwap_80211_macoperation_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_80211_MACOPERATION_ELEMENT(x)					({	\
																		struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_80211_MACOPERATION);	\
																		f->create(x, sizeof(struct capwap_80211_macoperation_element));	\
																	})
														
#endif /* __CAPWAP_ELEMENT_80211_MACOPERATION_HEADER__ */
