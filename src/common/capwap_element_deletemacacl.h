#ifndef __CAPWAP_ELEMENT_DELETE_MAC_ACL__HEADER__
#define __CAPWAP_ELEMENT_DELETE_MAC_ACL__HEADER__

#define CAPWAP_ELEMENT_DELETEMACACL				17

struct capwap_deletemacacl_element {
	uint8_t entry;
	uint8_t length;
	uint8_t* address;
};

extern const struct capwap_message_elements_ops capwap_element_deletemacacl_ops;

#endif /* __CAPWAP_ELEMENT_DELETE_MAC_ACL__HEADER__ */
