#ifndef __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__
#define __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__

#define CAPWAP_ELEMENT_MTUDISCOVERY			52

struct capwap_mtudiscovery_element {
	uint16_t length;
};

extern struct capwap_message_elements_ops capwap_element_mtudiscovery_ops;

#endif /* __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__ */
