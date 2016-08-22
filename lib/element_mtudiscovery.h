#ifndef __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__
#define __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__

#define CAPWAP_ELEMENT_MTUDISCOVERY_VENDOR			0
#define CAPWAP_ELEMENT_MTUDISCOVERY_TYPE			52
#define CAPWAP_ELEMENT_MTUDISCOVERY				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_MTUDISCOVERY_VENDOR, .type = CAPWAP_ELEMENT_MTUDISCOVERY_TYPE }


struct capwap_mtudiscovery_element {
	uint16_t length;
};

extern const struct capwap_message_elements_ops capwap_element_mtudiscovery_ops;

#endif /* __CAPWAP_ELEMENT_MTUDISCOVERY_HEADER__ */
