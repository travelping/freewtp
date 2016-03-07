#ifndef __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__
#define __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__

#define CAPWAP_ELEMENT_MAXIMUMLENGTH			29

struct capwap_maximumlength_element {
	uint16_t length;
};

extern const struct capwap_message_elements_ops capwap_element_maximumlength_ops;

#endif /* __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__ */
