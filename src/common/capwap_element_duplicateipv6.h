#ifndef __CAPWAP_ELEMENT_DUPLICATE_IPv6__HEADER__
#define __CAPWAP_ELEMENT_DUPLICATE_IPv6__HEADER__

#define CAPWAP_ELEMENT_DUPLICATEIPV6			22

#define CAPWAP_DUPLICATEIPv6_CLEARED			0
#define CAPWAP_DUPLICATEIPv6_DETECTED			1

struct capwap_duplicateipv6_element {
	struct in6_addr address;
	uint8_t status;
	uint8_t length;
	uint8_t* macaddress;
};

extern const struct capwap_message_elements_ops capwap_element_duplicateipv6_ops;

#endif /* __CAPWAP_ELEMENT_DUPLICATE_IPv6__HEADER__ */
