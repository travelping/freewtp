#ifndef __CAPWAP_ELEMENT_LOCALIPV4_HEADER__
#define __CAPWAP_ELEMENT_LOCALIPV4_HEADER__

#define CAPWAP_ELEMENT_LOCALIPV4_VENDOR							0
#define CAPWAP_ELEMENT_LOCALIPV4_TYPE							30
#define CAPWAP_ELEMENT_LOCALIPV4								(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_LOCALIPV4_VENDOR, .type = CAPWAP_ELEMENT_LOCALIPV4_TYPE }


struct capwap_localipv4_element {
	struct in_addr address;
};

extern const struct capwap_message_elements_ops capwap_element_localipv4_ops;

#endif /* __CAPWAP_ELEMENT_LOCALIPV4_HEADER__ */
