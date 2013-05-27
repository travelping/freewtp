#ifndef __CAPWAP_ELEMENT_WTPNAME_HEADER__
#define __CAPWAP_ELEMENT_WTPNAME_HEADER__

#define CAPWAP_ELEMENT_WTPNAME			45

#define CAPWAP_WTPNAME_MAXLENGTH		512

struct capwap_wtpname_element {
	uint8_t name[CAPWAP_WTPNAME_MAXLENGTH + 1];
};

extern struct capwap_message_elements_ops capwap_element_wtpname_ops;

#endif /* __CAPWAP_ELEMENT_WTPNAME_HEADER__ */
