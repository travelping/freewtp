#ifndef __CAPWAP_ELEMENT_ADD_STATION__HEADER__
#define __CAPWAP_ELEMENT_ADD_STATION__HEADER__

#define CAPWAP_ELEMENT_ADDSTATION				8

#define CAPWAP_ADDSTATION_VLAN_MAX_LENGTH		512

struct capwap_addstation_element {
	uint8_t radioid;
	uint8_t length;
	uint8_t* address;
	uint8_t* vlan;
};

extern struct capwap_message_elements_ops capwap_element_addstation_ops;

#endif /* __CAPWAP_ELEMENT_ADD_STATION__HEADER__ */
