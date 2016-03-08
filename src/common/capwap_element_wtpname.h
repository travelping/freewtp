#ifndef __CAPWAP_ELEMENT_WTPNAME_HEADER__
#define __CAPWAP_ELEMENT_WTPNAME_HEADER__

#define CAPWAP_ELEMENT_WTPNAME_VENDOR			0
#define CAPWAP_ELEMENT_WTPNAME_TYPE			45
#define CAPWAP_ELEMENT_WTPNAME				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_WTPNAME_VENDOR, .type = CAPWAP_ELEMENT_WTPNAME_TYPE }


#define CAPWAP_WTPNAME_MAXLENGTH		512

struct capwap_wtpname_element {
	uint8_t* name;
};

extern const struct capwap_message_elements_ops capwap_element_wtpname_ops;

#endif /* __CAPWAP_ELEMENT_WTPNAME_HEADER__ */
