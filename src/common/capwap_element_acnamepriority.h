#ifndef __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__
#define __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__

#define CAPWAP_ELEMENT_ACNAMEPRIORITY_VENDOR			0
#define CAPWAP_ELEMENT_ACNAMEPRIORITY_TYPE			5
#define CAPWAP_ELEMENT_ACNAMEPRIORITY				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_ACNAMEPRIORITY_VENDOR, .type = CAPWAP_ELEMENT_ACNAMEPRIORITY_TYPE }


#define CAPWAP_ACNAMEPRIORITY_MAXLENGTH			512

struct capwap_acnamepriority_element {
	uint8_t priority;
	uint8_t* name;
};

extern const struct capwap_message_elements_ops capwap_element_acnamepriority_ops;

#endif /* __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__ */
