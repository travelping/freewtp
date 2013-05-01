#ifndef __CAPWAP_ELEMENT_LOCATION_HEADER__
#define __CAPWAP_ELEMENT_LOCATION_HEADER__

#define CAPWAP_ELEMENT_LOCATION			28

#define CAPWAP_LOCATION_MAXLENGTH		1024

struct capwap_location_element {
	char value[CAPWAP_LOCATION_MAXLENGTH + 1];
};

struct capwap_message_element* capwap_location_element_create(void* data, unsigned long datalength);
int capwap_location_element_validate(struct capwap_message_element* element);
void* capwap_location_element_parsing(struct capwap_message_element* element);
void capwap_location_element_free(void* data);


/* Helper */
#define CAPWAP_CREATE_LOCATION_ELEMENT(x)				({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_LOCATION);	\
															f->create(x, sizeof(struct capwap_location_element));	\
														})

#endif /* __CAPWAP_ELEMENT_LOCATION_HEADER__ */
