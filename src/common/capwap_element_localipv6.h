#ifndef __CAPWAP_ELEMENT_LOCALIPV6_HEADER__
#define __CAPWAP_ELEMENT_LOCALIPV6_HEADER__

#define CAPWAP_ELEMENT_LOCALIPV6						50

struct capwap_localipv6_element {
	struct in6_addr address;
};

extern struct capwap_message_elements_ops capwap_element_localipv6_ops;

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
