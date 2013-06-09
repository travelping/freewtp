#ifndef __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__
#define __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__

#define CAPWAP_ELEMENT_ACNAMEPRIORITY			5

#define CAPWAP_ACNAMEPRIORITY_MAXLENGTH			512

struct capwap_acnamepriority_element {
	uint8_t priority;
	uint8_t* name;
};

extern struct capwap_message_elements_ops capwap_element_acnamepriority_ops;

#endif /* __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__ */
