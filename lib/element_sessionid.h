#ifndef __CAPWAP_ELEMENT_SESSIONID_HEADER__
#define __CAPWAP_ELEMENT_SESSIONID_HEADER__

#define CAPWAP_ELEMENT_SESSIONID_VENDOR		0
#define CAPWAP_ELEMENT_SESSIONID_TYPE		35
#define CAPWAP_ELEMENT_SESSIONID			(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_SESSIONID_VENDOR, .type = CAPWAP_ELEMENT_SESSIONID_TYPE }


struct capwap_sessionid_element {
	uint8_t id[16];
};

/* */
void capwap_sessionid_generate(struct capwap_sessionid_element* session);
void capwap_sessionid_printf(struct capwap_sessionid_element* session, char* string);

extern const struct capwap_message_elements_ops capwap_element_sessionid_ops;

#endif /* __CAPWAP_ELEMENT_SESSIONID_HEADER__ */
