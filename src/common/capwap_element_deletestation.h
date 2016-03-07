#ifndef __CAPWAP_ELEMENT_DELETE_STATION__HEADER__
#define __CAPWAP_ELEMENT_DELETE_STATION__HEADER__

#define CAPWAP_ELEMENT_DELETESTATION				18

struct capwap_deletestation_element {
	uint8_t radioid;
	uint8_t length;
	uint8_t* address;
};

extern const struct capwap_message_elements_ops capwap_element_deletestation_ops;

#endif /* __CAPWAP_ELEMENT_DELETE_STATION__HEADER__ */
