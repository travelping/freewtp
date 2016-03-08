#ifndef __CAPWAP_ELEMENT_DUPLICATE_IPv4__HEADER__
#define __CAPWAP_ELEMENT_DUPLICATE_IPv4__HEADER__

#define CAPWAP_ELEMENT_DUPLICATEIPV4_VENDOR			0
#define CAPWAP_ELEMENT_DUPLICATEIPV4_TYPE			21
#define CAPWAP_ELEMENT_DUPLICATEIPV4				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_DUPLICATEIPV4_VENDOR, .type = CAPWAP_ELEMENT_DUPLICATEIPV4_TYPE }


#define CAPWAP_DUPLICATEIPv4_CLEARED			0
#define CAPWAP_DUPLICATEIPv4_DETECTED			1

struct capwap_duplicateipv4_element {
	struct in_addr address;
	uint8_t status;
	uint8_t length;
	uint8_t* macaddress;
};

extern const struct capwap_message_elements_ops capwap_element_duplicateipv4_ops;

#endif /* __CAPWAP_ELEMENT_DUPLICATE_IPv4__HEADER__ */
