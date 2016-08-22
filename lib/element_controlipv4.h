#ifndef __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__
#define __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__

#define CAPWAP_ELEMENT_CONTROLIPV4_VENDOR							0
#define CAPWAP_ELEMENT_CONTROLIPV4_TYPE							10
#define CAPWAP_ELEMENT_CONTROLIPV4								(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_CONTROLIPV4_VENDOR, .type = CAPWAP_ELEMENT_CONTROLIPV4_TYPE }


struct capwap_controlipv4_element {
	struct in_addr address;
	uint16_t wtpcount;
};

extern const struct capwap_message_elements_ops capwap_element_controlipv4_ops;

#endif /* __CAPWAP_ELEMENT_CONTROLIPV4_HEADER__ */
