#ifndef __CAPWAP_ELEMENT_TIMERS_HEADER__
#define __CAPWAP_ELEMENT_TIMERS_HEADER__

#define CAPWAP_ELEMENT_TIMERS				12

struct capwap_timers_element {
	unsigned char discovery;
	unsigned char echorequest;
};

struct capwap_message_element* capwap_timers_element_create(void* data, unsigned long length);
int capwap_timers_element_validate(struct capwap_message_element* element);
void* capwap_timers_element_parsing(struct capwap_message_element* element);
void capwap_timers_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_TIMERS_ELEMENT(x)				({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_TIMERS);	\
														f->create(x, sizeof(struct capwap_timers_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_TIMERS_HEADER__ */
