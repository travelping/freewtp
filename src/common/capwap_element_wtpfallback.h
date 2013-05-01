#ifndef __CAPWAP_ELEMENT_WTPFALLBACK_HEADER__
#define __CAPWAP_ELEMENT_WTPFALLBACK_HEADER__

#define CAPWAP_ELEMENT_WTPFALLBACK			40

struct capwap_wtpfallback_element {
	char mode;
};

#define CAPWAP_WTP_FALLBACK_ENABLED			1
#define CAPWAP_WTP_FALLBACK_DISABLED		2

struct capwap_message_element* capwap_wtpfallback_element_create(void* data, unsigned long length);
int capwap_wtpfallback_element_validate(struct capwap_message_element* element);
void* capwap_wtpfallback_element_parsing(struct capwap_message_element* element);
void capwap_wtpfallback_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_WTPFALLBACK_ELEMENT(x)		({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPFALLBACK);	\
														f->create(x, sizeof(struct capwap_ecnsupport_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_WTPFALLBACK_HEADER__ */
