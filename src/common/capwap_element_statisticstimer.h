#ifndef __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__
#define __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__

#define CAPWAP_ELEMENT_STATISTICSTIMER			36

struct capwap_statisticstimer_element {
	uint16_t timer;
};

extern struct capwap_message_elements_ops capwap_element_statisticstimer_ops;

#endif /* __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__ */
