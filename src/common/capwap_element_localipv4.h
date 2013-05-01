#ifndef __CAPWAP_ELEMENT_LOCALIPV4_HEADER__
#define __CAPWAP_ELEMENT_LOCALIPV4_HEADER__

#define CAPWAP_ELEMENT_LOCALIPV4							30

struct capwap_localipv4_element {
	struct in_addr address;
};

struct capwap_message_element* capwap_localipv4_element_create(void* data, unsigned long datalength);
int capwap_localipv4_element_validate(struct capwap_message_element* element);
void* capwap_localipv4_element_parsing(struct capwap_message_element* element);
void capwap_localipv4_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_LOCALIPV4_ELEMENT(x)				({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_LOCALIPV4);	\
															f->create(x, sizeof(struct capwap_localipv4_element));	\
														})

#endif /* __CAPWAP_ELEMENT_LOCALIPV4_HEADER__ */
