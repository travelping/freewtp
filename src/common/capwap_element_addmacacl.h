#ifndef __CAPWAP_ELEMENT_ADD_MAC_ACL__HEADER__
#define __CAPWAP_ELEMENT_ADD_MAC_ACL__HEADER__

#define CAPWAP_ELEMENT_ADDMACACL				7

struct capwap_addmacacl_element {
	uint8_t entry;
	uint8_t length;
	uint8_t* address;
};

extern struct capwap_message_elements_ops capwap_element_addmacacl_ops;

#endif /* __CAPWAP_ELEMENT_ADD_MAC_ACL__HEADER__ */
