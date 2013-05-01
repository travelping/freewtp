#ifndef __CAPWAP_ELEMENT_LOCALIPV6_HEADER__
#define __CAPWAP_ELEMENT_LOCALIPV6_HEADER__

#define CAPWAP_ELEMENT_LOCALIPV6						50

struct capwap_localipv6_element {
	struct in6_addr address;
};

struct capwap_message_element* capwap_localipv6_element_create(void* data, unsigned long datalength);
int capwap_localipv6_element_validate(struct capwap_message_element* element);
void* capwap_localipv6_element_parsing(struct capwap_message_element* element);
void capwap_localipv6_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_LOCALIPV6_ELEMENT(x)				({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_LOCALIPV6);	\
															f->create(x, sizeof(struct capwap_localipv6_element));	\
														})

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
