#ifndef __CAPWAP_ELEMENT_DECRYPT_ERROR_REPORT__HEADER__
#define __CAPWAP_ELEMENT_DECRYPT_ERROR_REPORT__HEADER__

#define CAPWAP_ELEMENT_DECRYPTERRORREPORT				15

struct capwap_decrypterrorreport_element {
	uint8_t radioid;
	uint8_t entry;
	uint8_t length;
	uint8_t* address;
};

extern struct capwap_message_elements_ops capwap_element_decrypterrorreport_ops;

#endif /* __CAPWAP_ELEMENT_DECRYPT_ERROR_REPORT__HEADER__ */
