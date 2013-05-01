#ifndef __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__
#define __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__

#define CAPWAP_ELEMENT_STATISTICSTIMER			36

struct capwap_statisticstimer_element {
	unsigned short timer;
};

struct capwap_message_element* capwap_statisticstimer_element_create(void* data, unsigned long length);
int capwap_statisticstimer_element_validate(struct capwap_message_element* element);
void* capwap_statisticstimer_element_parsing(struct capwap_message_element* element);
void capwap_statisticstimer_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_STATISTICSTIMER_ELEMENT(x)	({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_STATISTICSTIMER);	\
														f->create(x, sizeof(struct capwap_statisticstimer_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_STATISTICSTIMER_HEADER__ */
