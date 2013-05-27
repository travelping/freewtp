#ifndef __CAPWAP_ELEMENT_TIMERS_HEADER__
#define __CAPWAP_ELEMENT_TIMERS_HEADER__

#define CAPWAP_ELEMENT_TIMERS				12

struct capwap_timers_element {
	uint8_t discovery;
	uint8_t echorequest;
};

extern struct capwap_message_elements_ops capwap_element_timers_ops;

#endif /* __CAPWAP_ELEMENT_TIMERS_HEADER__ */
