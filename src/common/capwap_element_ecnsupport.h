#ifndef __CAPWAP_ELEMENT_ECNSUPPORT_HEADER__
#define __CAPWAP_ELEMENT_ECNSUPPORT_HEADER__

#define CAPWAP_ELEMENT_ECNSUPPORT			53

struct capwap_ecnsupport_element {
	char flag;
};

#define CAPWAP_LIMITED_ECN_SUPPORT			0
#define CAPWAP_FULL_ECN_SUPPORT				1

struct capwap_message_element* capwap_ecnsupport_element_create(void* data, unsigned long length);
int capwap_ecnsupport_element_validate(struct capwap_message_element* element);
void* capwap_ecnsupport_element_parsing(struct capwap_message_element* element);
void capwap_ecnsupport_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_ECNSUPPORT_ELEMENT(x)			({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_ECNSUPPORT);	\
														f->create(x, sizeof(struct capwap_ecnsupport_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_ECNSUPPORT_HEADER__ */
