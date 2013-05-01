#ifndef __CAPWAP_ELEMENT_WTPMACTYPE_HEADER__
#define __CAPWAP_ELEMENT_WTPMACTYPE_HEADER__

#define CAPWAP_ELEMENT_WTPMACTYPE			44

struct capwap_wtpmactype_element {
	char type;
};

#define CAPWAP_LOCALMAC				0
#define CAPWAP_SPLITMAC				1

struct capwap_message_element* capwap_wtpmactype_element_create(void* data, unsigned long length);
int capwap_wtpmactype_element_validate(struct capwap_message_element* element);
void* capwap_wtpmactype_element_parsing(struct capwap_message_element* element);
void capwap_wtpmactype_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_WTPMACTYPE_ELEMENT(x)			({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPMACTYPE);	\
														f->create(x, sizeof(struct capwap_wtpmactype_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_WTPMACTYPE_HEADER__ */
