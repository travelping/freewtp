#ifndef __CAPWAP_ELEMENT_CONTROLIPV6_HEADER__
#define __CAPWAP_ELEMENT_CONTROLIPV6_HEADER__

#define CAPWAP_ELEMENT_CONTROLIPV6							11

struct capwap_controlipv6_element {
	struct in6_addr address;
	unsigned short wtpcount;
};

struct capwap_message_element* capwap_controlipv6_element_create(void* data, unsigned long datalength);
int capwap_controlipv6_element_validate(struct capwap_message_element* element);
void* capwap_controlipv6_element_parsing(struct capwap_message_element* element);
void capwap_controlipv6_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_CONTROLIPV6_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_CONTROLIPV6);	\
															f->create(x, sizeof(struct capwap_controlipv6_element));	\
														})

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
