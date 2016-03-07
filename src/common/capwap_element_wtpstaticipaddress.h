#ifndef __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__
#define __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__

#define CAPWAP_ELEMENT_WTPSTATICIPADDRESS		49

struct capwap_wtpstaticipaddress_element {
	struct in_addr address;
	struct in_addr netmask;
	struct in_addr gateway;
	uint8_t staticip;
};

extern const struct capwap_message_elements_ops capwap_element_wtpstaticipaddress_ops;

#endif /* __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__ */
