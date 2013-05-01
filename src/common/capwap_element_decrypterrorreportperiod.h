#ifndef __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__
#define __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__

#define CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD			16

struct capwap_decrypterrorreportperiod_element {
	unsigned char radioid;
	unsigned short interval;
};

struct capwap_message_element* capwap_decrypterrorreportperiod_element_create(void* data, unsigned long length);
int capwap_decrypterrorreportperiod_element_validate(struct capwap_message_element* element);
void* capwap_decrypterrorreportperiod_element_parsing(struct capwap_message_element* element);
void capwap_decrypterrorreportperiod_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_DECRYPTERRORREPORTPERIOD_ELEMENT(x)		({	\
																	struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD);	\
																	f->create(x, sizeof(struct capwap_decrypterrorreportperiod_element));	\
																})
														
#endif /* __CAPWAP_ELEMENT_DECRYPTERRORREPORTPERIOD_HEADER__ */
