#ifndef __CAPWAP_ELEMENT_ADD_MAC_ACL__HEADER__
#define __CAPWAP_ELEMENT_ADD_MAC_ACL__HEADER__

#define CAPWAP_ELEMENT_ADDMACACL_VENDOR				0
#define CAPWAP_ELEMENT_ADDMACACL_TYPE				7
#define CAPWAP_ELEMENT_ADDMACACL					(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_ADDMACACL_VENDOR, .type = CAPWAP_ELEMENT_ADDMACACL_TYPE }


struct capwap_addmacacl_element {
	uint8_t entry;
	uint8_t length;
	uint8_t* address;
};

extern const struct capwap_message_elements_ops capwap_element_addmacacl_ops;

#endif /* __CAPWAP_ELEMENT_ADD_MAC_ACL__HEADER__ */
