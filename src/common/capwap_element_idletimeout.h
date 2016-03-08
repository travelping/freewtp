#ifndef __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__
#define __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__

#define CAPWAP_ELEMENT_IDLETIMEOUT_VENDOR			0
#define CAPWAP_ELEMENT_IDLETIMEOUT_TYPE			23
#define CAPWAP_ELEMENT_IDLETIMEOUT				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_IDLETIMEOUT_VENDOR, .type = CAPWAP_ELEMENT_IDLETIMEOUT_TYPE }


struct capwap_idletimeout_element {
	uint32_t timeout;
};

extern const struct capwap_message_elements_ops capwap_element_idletimeout_ops;

#endif /* __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__ */
