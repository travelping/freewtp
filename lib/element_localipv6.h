#ifndef __CAPWAP_ELEMENT_LOCALIPV6_HEADER__
#define __CAPWAP_ELEMENT_LOCALIPV6_HEADER__

#define CAPWAP_ELEMENT_LOCALIPV6_VENDOR						0
#define CAPWAP_ELEMENT_LOCALIPV6_TYPE						50
#define CAPWAP_ELEMENT_LOCALIPV6							(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_LOCALIPV6_VENDOR, .type = CAPWAP_ELEMENT_LOCALIPV6_TYPE }


struct capwap_localipv6_element {
	struct in6_addr address;
};

extern const struct capwap_message_elements_ops capwap_element_localipv6_ops;

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
