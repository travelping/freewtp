#ifndef __CAPWAP_ELEMENT_LOCALIPV4_HEADER__
#define __CAPWAP_ELEMENT_LOCALIPV4_HEADER__

#define CAPWAP_ELEMENT_LOCALIPV4							30

struct capwap_localipv4_element {
	struct in_addr address;
};

extern struct capwap_message_elements_ops capwap_element_localipv4_ops;

#endif /* __CAPWAP_ELEMENT_LOCALIPV4_HEADER__ */
