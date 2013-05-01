#ifndef __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__
#define __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__

#define CAPWAP_ELEMENT_ACNAMEPRIORITY			5

#define CAPWAP_ACNAMEPRIORITY_MAXLENGTH			512

struct capwap_acnamepriority_element {
	unsigned char priority;
	char name[CAPWAP_ACNAMEPRIORITY_MAXLENGTH + 1];
};

struct capwap_message_element* capwap_acnamepriority_element_create(void* data, unsigned long datalength);
int capwap_acnamepriority_element_validate(struct capwap_message_element* element);
void* capwap_acnamepriority_element_parsing(struct capwap_message_element* element);
void capwap_acnamepriority_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_ACNAMEPRIORITY_ELEMENT(x)			({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_ACNAMEPRIORITY);	\
															f->create(x, sizeof(struct capwap_acnamepriority_element));	\
														})

#endif /* __CAPWAP_ELEMENT_ACNAMEPRIORITY_HEADER__ */
