#ifndef __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__
#define __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__

#define CAPWAP_ELEMENT_MTUDISCOVERY			52

struct capwap_mtudiscovery_element {
	unsigned short length;
};

struct capwap_message_element* capwap_mtudiscovery_element_create(void* data, unsigned long length);
int capwap_mtudiscovery_element_validate(struct capwap_message_element* element);
void* capwap_mtudiscovery_element_parsing(struct capwap_message_element* element);
void capwap_mtudiscovery_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_MTUDISCOVERY_ELEMENT(x)		({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_MTUDISCOVERY);	\
														f->create(x, sizeof(struct capwap_mtudiscovery_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__ */
