#ifndef __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__
#define __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__

#define CAPWAP_ELEMENT_ACIPV4LIST_VENDOR							0
#define CAPWAP_ELEMENT_ACIPV4LIST_TYPE							2
#define CAPWAP_ELEMENT_ACIPV4LIST								(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_ACIPV4LIST_VENDOR, .type = CAPWAP_ELEMENT_ACIPV4LIST_TYPE }


#define CAPWAP_ACIPV4LIST_MAX_ELEMENTS						1024

struct capwap_acipv4list_element {
	struct capwap_array* addresses;
};

extern const struct capwap_message_elements_ops capwap_element_acipv4list_ops;

#endif /* __CAPWAP_ELEMENT_ACIPV4LIST_HEADER__ */
