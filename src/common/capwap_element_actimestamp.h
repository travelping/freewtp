#ifndef __CAPWAP_ELEMENT_AC_TIMESTAMP_HEADER__
#define __CAPWAP_ELEMENT_AC_TIMESTAMP_HEADER__

#define CAPWAP_ELEMENT_ACTIMESTAMP_VENDOR			0
#define CAPWAP_ELEMENT_ACTIMESTAMP_TYPE			6
#define CAPWAP_ELEMENT_ACTIMESTAMP				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_ACTIMESTAMP_VENDOR, .type = CAPWAP_ELEMENT_ACTIMESTAMP_TYPE }



struct capwap_actimestamp_element {
	uint32_t timestamp;
};

extern const struct capwap_message_elements_ops capwap_element_actimestamp_ops;

#endif /* __CAPWAP_ELEMENT_AC_TIMESTAMP_HEADER__ */
