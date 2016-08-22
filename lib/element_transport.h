#ifndef __CAPWAP_ELEMENT_TRANSPORT_HEADER__
#define __CAPWAP_ELEMENT_TRANSPORT_HEADER__

#define CAPWAP_ELEMENT_TRANSPORT_VENDOR			0
#define CAPWAP_ELEMENT_TRANSPORT_TYPE			51
#define CAPWAP_ELEMENT_TRANSPORT				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_TRANSPORT_VENDOR, .type = CAPWAP_ELEMENT_TRANSPORT_TYPE }


#define CAPWAP_UDPLITE_TRANSPORT		1
#define CAPWAP_UDP_TRANSPORT			2

struct capwap_transport_element {
	uint8_t type;
};

extern const struct capwap_message_elements_ops capwap_element_transport_ops;

#endif /* __CAPWAP_ELEMENT_TRANSPORT_HEADER__ */
