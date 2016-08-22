#ifndef __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__
#define __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__

#define CAPWAP_ELEMENT_STATISTICSTIMER_VENDOR			0
#define CAPWAP_ELEMENT_STATISTICSTIMER_TYPE			36
#define CAPWAP_ELEMENT_STATISTICSTIMER				(struct capwap_message_element_id){ .vendor = CAPWAP_ELEMENT_STATISTICSTIMER_VENDOR, .type = CAPWAP_ELEMENT_STATISTICSTIMER_TYPE }


struct capwap_statisticstimer_element {
	uint16_t timer;
};

extern const struct capwap_message_elements_ops capwap_element_statisticstimer_ops;

#endif /* __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__ */
