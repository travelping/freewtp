#ifndef __CAPWAP_ELEMENT_LOCATION_HEADER__
#define __CAPWAP_ELEMENT_LOCATION_HEADER__

#define CAPWAP_ELEMENT_LOCATION_VENDOR			0
#define CAPWAP_ELEMENT_LOCATION_TYPE			28
#define CAPWAP_ELEMENT_LOCATION				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_LOCATION_VENDOR, .type = CAPWAP_ELEMENT_LOCATION_TYPE }


#define CAPWAP_LOCATION_MAXLENGTH		1024

struct capwap_location_element {
	uint8_t* value;
};

extern const struct capwap_message_elements_ops capwap_element_location_ops;

#endif /* __CAPWAP_ELEMENT_LOCATION_HEADER__ */
