#ifndef __CAPWAP_ELEMENT_DISCOVERYTYPE_HEADER__
#define __CAPWAP_ELEMENT_DISCOVERYTYPE_HEADER__

#define CAPWAP_ELEMENT_DISCOVERYTYPE			20

#define CAPWAP_ELEMENT_DISCOVERYTYPE_TYPE_UNKNOWN			0
#define CAPWAP_ELEMENT_DISCOVERYTYPE_TYPE_STATIC			1
#define CAPWAP_ELEMENT_DISCOVERYTYPE_TYPE_DHCP				2
#define CAPWAP_ELEMENT_DISCOVERYTYPE_TYPE_DNS				3
#define CAPWAP_ELEMENT_DISCOVERYTYPE_TYPE_ACREFERRAL		4

struct capwap_discoverytype_element {
	unsigned char type;
};

struct capwap_message_element* capwap_discoverytype_element_create(void* data, unsigned long datalength);
int capwap_discoverytype_element_validate(struct capwap_message_element* element);
void* capwap_discoverytype_element_parsing(struct capwap_message_element* element);
void capwap_discoverytype_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_DISCOVERYTYPE_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_DISCOVERYTYPE);	\
															f->create(x, sizeof(struct capwap_discoverytype_element));	\
														})

#endif /* __CAPWAP_ELEMENT_DISCOVERYTYPE_HEADER__ */
