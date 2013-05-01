#ifndef __CAPWAP_ELEMENT_RETURNEDMESSAGE_HEADER__
#define __CAPWAP_ELEMENT_RETURNEDMESSAGE_HEADER__

#define CAPWAP_ELEMENT_RETURNEDMESSAGE			34

#define CAPWAP_REASON_UNKNOWN_MESSAGE_ELEMENT					1
#define CAPWAP_REASON_UNSUPPORTED_MESSAGE_ELEMENT				2
#define CAPWAP_REASON_UNKNOWN_MESSAGE_ELEMENT_VALUE				3
#define CAPWAP_REASON_UNSUPPORTED_MESSAGE_ELEMENT_VALUE			4

#define CAPWAP_RETURNED_MESSAGE_MAX_LENGTH						255
     
struct capwap_returnedmessage_element {
	unsigned char reason;
	unsigned char length;
	char message[CAPWAP_RETURNED_MESSAGE_MAX_LENGTH];
};

struct capwap_message_element* capwap_returnedmessage_element_create(void* data, unsigned long length);
int capwap_returnedmessage_element_validate(struct capwap_message_element* element);
void* capwap_returnedmessage_element_parsing(struct capwap_message_element* element);
void capwap_returnedmessage_element_free(void* data);

/* Helper */
#define CAPWAP_CREATE_RETURNEDMESSAGE_ELEMENT(x)	({	\
														struct capwap_message_elements_func* f = capwap_get_message_element(CAPWAP_ELEMENT_RETURNEDMESSAGE);	\
														f->create(x, sizeof(struct capwap_returnedmessage_element));	\
													})
														
#endif /* __CAPWAP_ELEMENT_RETURNEDMESSAGE_HEADER__ */
