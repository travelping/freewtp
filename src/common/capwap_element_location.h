#ifndef __CAPWAP_ELEMENT_LOCATION_HEADER__
#define __CAPWAP_ELEMENT_LOCATION_HEADER__

#define CAPWAP_ELEMENT_LOCATION			28

#define CAPWAP_LOCATION_MAXLENGTH		1024

struct capwap_location_element {
	uint8_t* value;
};

extern struct capwap_message_elements_ops capwap_element_location_ops;

#endif /* __CAPWAP_ELEMENT_LOCATION_HEADER__ */
