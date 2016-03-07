#ifndef __CAPWAP_ELEMENT_RADIOADMSTATE_HEADER__
#define __CAPWAP_ELEMENT_RADIOADMSTATE_HEADER__

#define CAPWAP_ELEMENT_RADIOADMSTATE		31

#define CAPWAP_RADIO_ADMIN_STATE_ENABLED		1
#define CAPWAP_RADIO_ADMIN_STATE_DISABLED		2

struct capwap_radioadmstate_element {
	uint8_t radioid;
	uint8_t state;
};

extern const struct capwap_message_elements_ops capwap_element_radioadmstate_ops;

#endif /* __CAPWAP_ELEMENT_RADIOADMSTATE_HEADER__ */
