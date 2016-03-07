#ifndef __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__
#define __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__

#define CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD			16

struct capwap_decrypterrorreportperiod_element {
	uint8_t radioid;
	uint16_t interval;
};

extern const struct capwap_message_elements_ops capwap_element_decrypterrorreportperiod_ops;

#endif /* __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__ */
