#ifndef __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__
#define __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__

#define CAPWAP_ELEMENT_WTPSTATICIPADDRESS_VENDOR		0
#define CAPWAP_ELEMENT_WTPSTATICIPADDRESS_TYPE		49
#define CAPWAP_ELEMENT_WTPSTATICIPADDRESS			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_WTPSTATICIPADDRESS_VENDOR, .type = CAPWAP_ELEMENT_WTPSTATICIPADDRESS_TYPE }


struct capwap_wtpstaticipaddress_element {
	struct in_addr address;
	struct in_addr netmask;
	struct in_addr gateway;
	uint8_t staticip;
};

extern const struct capwap_message_elements_ops capwap_element_wtpstaticipaddress_ops;

#endif /* __CAPWAP_ELEMENT_WTPSTATICIPADDRESS_HEADER__ */
