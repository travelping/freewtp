#ifndef __CAPWAP_ELEMENT_SESSIONID_HEADER__
#define __CAPWAP_ELEMENT_SESSIONID_HEADER__

#define CAPWAP_ELEMENT_SESSIONID		35

struct capwap_sessionid_element {
	unsigned char id[16];
};

struct capwap_message_element* capwap_sessionid_element_create(void* data, unsigned long datalength);
int capwap_sessionid_element_validate(struct capwap_message_element* element);
void* capwap_sessionid_element_parsing(struct capwap_message_element* element);
void capwap_sessionid_element_free(void* data);

void capwap_sessionid_generate(struct capwap_sessionid_element* session);
void capwap_sessionid_printf(struct capwap_sessionid_element* session, char* string);

/* Helper */
#define CAPWAP_CREATE_SESSIONID_ELEMENT(x)				({	\
															struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_SESSIONID);	\
															f->create(x, sizeof(struct capwap_sessionid_element));	\
														})

#endif /* __CAPWAP_ELEMENT_SESSIONID_HEADER__ */
