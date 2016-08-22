#ifndef __CAPWAP_ELEMENT_DECRYPT_ERROR_REPORT__HEADER__
#define __CAPWAP_ELEMENT_DECRYPT_ERROR_REPORT__HEADER__

#define CAPWAP_ELEMENT_DECRYPTERRORREPORT_VENDOR				0
#define CAPWAP_ELEMENT_DECRYPTERRORREPORT_TYPE				15
#define CAPWAP_ELEMENT_DECRYPTERRORREPORT					(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_DECRYPTERRORREPORT_VENDOR, .type = CAPWAP_ELEMENT_DECRYPTERRORREPORT_TYPE }


struct capwap_decrypterrorreport_element {
	uint8_t radioid;
	uint8_t entry;
	uint8_t length;
	uint8_t* address;
};

extern const struct capwap_message_elements_ops capwap_element_decrypterrorreport_ops;

#endif /* __CAPWAP_ELEMENT_DECRYPT_ERROR_REPORT__HEADER__ */
