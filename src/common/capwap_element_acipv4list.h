#ifndef __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__
#define __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__

#define CAPWAP_ELEMENT_ACIPV4LIST							2

#define CAPWAP_ACIPV4LIST_MAX_ELEMENTS						1024

struct capwap_acipv4list_element {
	struct capwap_array* addresses;
};

extern struct capwap_message_elements_ops capwap_element_acipv4list_ops;

#endif /* __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__ */
