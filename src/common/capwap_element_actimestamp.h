#ifndef __CAPWAP_ELEMENT_AC_TIMESTAMP_HEADER__
#define __CAPWAP_ELEMENT_AC_TIMESTAMP_HEADER__

#define CAPWAP_ELEMENT_ACTIMESTAMP			6


struct capwap_actimestamp_element {
	uint32_t timestamp;
};

extern struct capwap_message_elements_ops capwap_element_actimestamp_ops;

#endif /* __CAPWAP_ELEMENT_AC_TIMESTAMP_HEADER__ */
