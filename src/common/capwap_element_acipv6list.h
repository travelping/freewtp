#ifndef __CAPWAP_ELEMENT_ACIPV6LIST_HEADER__
#define __CAPWAP_ELEMENT_ACIPV6LIST_HEADER__

#define CAPWAP_ELEMENT_ACIPV6LIST_VENDOR							0
#define CAPWAP_ELEMENT_ACIPV6LIST_TYPE							3
#define CAPWAP_ELEMENT_ACIPV6LIST								(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_ACIPV6LIST_VENDOR, .type = CAPWAP_ELEMENT_ACIPV6LIST_TYPE }


#define CAPWAP_ACIPV6LIST_MAX_ELEMENTS						1024

struct capwap_acipv6list_element {
	struct capwap_array* addresses;
};

extern const struct capwap_message_elements_ops capwap_element_acipv6list_ops;

#endif /* __CAPWAP_ELEMENT_ACIPV6LIST_HEADER__ */
