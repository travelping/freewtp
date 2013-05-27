#ifndef __CAPWAP_ELEMENT_CONTROLIPV6_HEADER__
#define __CAPWAP_ELEMENT_CONTROLIPV6_HEADER__

#define CAPWAP_ELEMENT_CONTROLIPV6							11

struct capwap_controlipv6_element {
	struct in6_addr address;
	unsigned short wtpcount;
};

extern struct capwap_message_elements_ops capwap_element_controlipv6_ops;

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
