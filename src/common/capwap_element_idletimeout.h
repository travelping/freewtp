#ifndef __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__
#define __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__

#define CAPWAP_ELEMENT_IDLETIMEOUT			23

struct capwap_idletimeout_element {
	unsigned long timeout;
};

struct capwap_message_element* capwap_idletimeout_element_create(void* data, unsigned long length);
int capwap_idletimeout_element_validate(struct capwap_message_element* element);
void* capwap_idletimeout_element_parsing(struct capwap_message_element* element);
void capwap_idletimeout_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_IDLETIMEOUT_ELEMENT(x)		({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_IDLETIMEOUT);	\
														f->create(x, sizeof(struct capwap_idletimeout_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__ */
