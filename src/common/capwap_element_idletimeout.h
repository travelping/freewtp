#ifndef __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__
#define __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__

#define CAPWAP_ELEMENT_IDLETIMEOUT			23

struct capwap_idletimeout_element {
	uint32_t timeout;
};

extern struct capwap_message_elements_ops capwap_element_idletimeout_ops;

#endif /* __CAPWAP_ELEMENT_IDLETIMEOUT_HEADER__ */
