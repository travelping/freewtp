#ifndef __CAPWAP_ELEMENT_CONTROLIPV6_HEADER__
#define __CAPWAP_ELEMENT_CONTROLIPV6_HEADER__

#define CAPWAP_ELEMENT_CONTROLIPV6_VENDOR							0
#define CAPWAP_ELEMENT_CONTROLIPV6_TYPE							11
#define CAPWAP_ELEMENT_CONTROLIPV6								(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_CONTROLIPV6_VENDOR, .type = CAPWAP_ELEMENT_CONTROLIPV6_TYPE }


struct capwap_controlipv6_element {
	struct in6_addr address;
	unsigned short wtpcount;
};

extern const struct capwap_message_elements_ops capwap_element_controlipv6_ops;

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
