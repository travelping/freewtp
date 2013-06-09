#ifndef __CAPWAP_ELEMENT_DISCOVERYTYPE_HEADER__
#define __CAPWAP_ELEMENT_DISCOVERYTYPE_HEADER__

#define CAPWAP_ELEMENT_DISCOVERYTYPE			20

#define CAPWAP_DISCOVERYTYPE_TYPE_UNKNOWN			0
#define CAPWAP_DISCOVERYTYPE_TYPE_STATIC			1
#define CAPWAP_DISCOVERYTYPE_TYPE_DHCP				2
#define CAPWAP_DISCOVERYTYPE_TYPE_DNS				3
#define CAPWAP_DISCOVERYTYPE_TYPE_ACREFERRAL		4

struct capwap_discoverytype_element {
	uint8_t type;
};

extern struct capwap_message_elements_ops capwap_element_discoverytype_ops;

#endif /* __CAPWAP_ELEMENT_DISCOVERYTYPE_HEADER__ */
