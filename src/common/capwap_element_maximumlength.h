#ifndef __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__
#define __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__

#define CAPWAP_ELEMENT_MAXIMUMLENGTH			29

struct capwap_maximumlength_element {
	unsigned short length;
};

struct capwap_message_element* capwap_maximumlength_element_create(void* data, unsigned long length);
int capwap_maximumlength_element_validate(struct capwap_message_element* element);
void* capwap_maximumlength_element_parsing(struct capwap_message_element* element);
void capwap_maximumlength_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_MAXIMUMLENGTH_ELEMENT(x)		({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_MAXIMUMLENGTH);	\
														f->create(x, sizeof(struct capwap_maximumlength_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__ */
