#ifndef __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__
#define __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__

#define CAPWAP_ELEMENT_IMAGEIDENTIFIER			25

#define CAPWAP_IMAGEIDENTIFIER_MAXLENGTH		1024

struct capwap_imageidentifier_element {
	unsigned long vendor;
	char name[CAPWAP_IMAGEIDENTIFIER_MAXLENGTH + 1];
};

struct capwap_message_element* capwap_imageidentifier_element_create(void* data, unsigned long datalength);
int capwap_imageidentifier_element_validate(struct capwap_message_element* element);
void* capwap_imageidentifier_element_parsing(struct capwap_message_element* element);
void capwap_imageidentifier_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_IMAGEIDENTIFIER_ELEMENT(x)		({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_IMAGEIDENTIFIER);	\
															f->create(x, sizeof(struct capwap_imageidentifier_element));	\
														})

#endif /* __CAPWAP_ELEMENT_IMAGEIDENTIFIER_HEADER__ */
