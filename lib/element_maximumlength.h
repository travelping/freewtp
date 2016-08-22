#ifndef __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__
#define __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__

#define CAPWAP_ELEMENT_MAXIMUMLENGTH_VENDOR			0
#define CAPWAP_ELEMENT_MAXIMUMLENGTH_TYPE			29
#define CAPWAP_ELEMENT_MAXIMUMLENGTH				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_MAXIMUMLENGTH_VENDOR, .type = CAPWAP_ELEMENT_MAXIMUMLENGTH_TYPE }


struct capwap_maximumlength_element {
	uint16_t length;
};

extern const struct capwap_message_elements_ops capwap_element_maximumlength_ops;

#endif /* __CAPWAP_ELEMENT_MAXIMUMLENGTH_HEADER__ */
