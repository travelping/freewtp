#ifndef __CAPWAP_ELEMENT_ACNAME_HEADER__
#define __CAPWAP_ELEMENT_ACNAME_HEADER__

#define CAPWAP_ELEMENT_ACNAME			4

#define CAPWAP_ACNAME_MAXLENGTH			512

struct capwap_acname_element {
	char name[CAPWAP_ACNAME_MAXLENGTH + 1];
};

struct capwap_message_element* capwap_acname_element_create(void* data, unsigned long datalength);
int capwap_acname_element_validate(struct capwap_message_element* element);
void* capwap_acname_element_parsing(struct capwap_message_element* element);
void capwap_acname_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_ACNAME_ELEMENT(x)					({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_ACNAME);	\
															f->create(x, sizeof(struct capwap_acname_element));	\
														})

#endif /* __CAPWAP_ELEMENT_ACNAME_HEADER__ */
