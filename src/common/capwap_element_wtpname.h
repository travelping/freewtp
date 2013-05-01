#ifndef __CAPWAP_ELEMENT_WTPNAME_HEADER__
#define __CAPWAP_ELEMENT_WTPNAME_HEADER__

#define CAPWAP_ELEMENT_WTPNAME			45

#define CAPWAP_WTPNAME_MAXLENGTH		512

struct capwap_wtpname_element {
	char name[CAPWAP_WTPNAME_MAXLENGTH + 1];
};

struct capwap_message_element* capwap_wtpname_element_create(void* data, unsigned long datalength);
int capwap_wtpname_element_validate(struct capwap_message_element* element);
void* capwap_wtpname_element_parsing(struct capwap_message_element* element);
void capwap_wtpname_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_WTPNAME_ELEMENT(x)				({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_WTPNAME);	\
															f->create(x, sizeof(struct capwap_wtpname_element));	\
														})

#endif /* __CAPWAP_ELEMENT_WTPNAME_HEADER__ */
