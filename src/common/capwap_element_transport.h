#ifndef __CAPWAP_ELEMENT_TRANSPORT_HEADER__
#define __CAPWAP_ELEMENT_TRANSPORT_HEADER__

#define CAPWAP_ELEMENT_TRANSPORT			51

struct capwap_transport_element {
	char type;
};

#define CAPWAP_UDPLITE_TRANSPORT		1
#define CAPWAP_UDP_TRANSPORT			2

struct capwap_message_element* capwap_transport_element_create(void* data, unsigned long length);
int capwap_transport_element_validate(struct capwap_message_element* element);
void* capwap_transport_element_parsing(struct capwap_message_element* element);
void capwap_transport_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_TRANSPORT_ELEMENT(x)			({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_TRANSPORT);	\
														f->create(x, sizeof(struct capwap_transport_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_TRANSPORT_HEADER__ */
