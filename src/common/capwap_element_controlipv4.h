#ifndef __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__
#define __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__

#define CAPWAP_ELEMENT_CONTROLIPV4							10

struct capwap_controlipv4_element {
	struct in_addr address;
	uint16_t wtpcount;
};

extern struct capwap_message_elements_ops capwap_element_controlipv4_ops;

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
