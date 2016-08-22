#ifndef __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__
#define __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__

#define CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_VENDOR			0
#define CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_TYPE			16
#define CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_VENDOR, .type = CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_TYPE }


struct capwap_decrypterrorreportperiod_element {
	uint8_t radioid;
	uint16_t interval;
};

extern const struct capwap_message_elements_ops capwap_element_decrypterrorreportperiod_ops;

#endif /* __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__ */
