#ifndef __CAPWAP_ELEMENT_TIMERS_HEADER__
#define __CAPWAP_ELEMENT_TIMERS_HEADER__

#define CAPWAP_ELEMENT_TIMERS_VENDOR				0
#define CAPWAP_ELEMENT_TIMERS_TYPE				12
#define CAPWAP_ELEMENT_TIMERS					(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_TIMERS_VENDOR, .type = CAPWAP_ELEMENT_TIMERS_TYPE }


struct capwap_timers_element {
	uint8_t discovery;
	uint8_t echorequest;
};

extern const struct capwap_message_elements_ops capwap_element_timers_ops;

#endif /* __CAPWAP_ELEMENT_TIMERS_HEADER__ */
