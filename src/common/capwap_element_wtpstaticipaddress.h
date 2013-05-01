#ifndef __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__
#define __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__

#define CAPWAP_ELEMENT_WTPSTATICIPADDRESS		49

struct capwap_wtpstaticipaddress_element {
	struct in_addr address;
	struct in_addr netmask;
	struct in_addr gateway;
	unsigned char staticip;
};

struct capwap_message_element* capwap_wtpstaticipaddress_element_create(void* data, unsigned long length);
int capwap_wtpstaticipaddress_element_validate(struct capwap_message_element* element);
void* capwap_wtpstaticipaddress_element_parsing(struct capwap_message_element* element);
void capwap_wtpstaticipaddress_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_WTPSTATICIPADDRESS_ELEMENT(x)		({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPSTATICIPADDRESS);	\
															f->create(x, sizeof(struct capwap_wtpstaticipaddress_element));	\
														})
														
#endif /* __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__ */
