#ifndef __CAPWAP_ELEMENT_ECNSUPPORT_HEADER__
#define __CAPWAP_ELEMENT_ECNSUPPORT_HEADER__

#define CAPWAP_ELEMENT_ECNSUPPORT_VENDOR			0
#define CAPWAP_ELEMENT_ECNSUPPORT_TYPE			53
#define CAPWAP_ELEMENT_ECNSUPPORT				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_ECNSUPPORT_VENDOR, .type = CAPWAP_ELEMENT_ECNSUPPORT_TYPE }


#define CAPWAP_LIMITED_ECN_SUPPORT			0
#define CAPWAP_FULL_ECN_SUPPORT				1

struct capwap_ecnsupport_element {
	uint8_t flag;
};

extern const struct capwap_message_elements_ops capwap_element_ecnsupport_ops;

#endif /* __CAPWAP_ELEMENT_ECNSUPPORT_HEADER__ */
