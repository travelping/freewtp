#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Reason     |    Length     |       Message Element...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   34 for Returned Message Element
Length:  >= 6

********************************************************************/

struct capwap_returnedmessage_raw_element {
	unsigned char reason;
	unsigned char length;
	char message[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_returnedmessage_element_create(void* data, unsigned long datalength) {
	unsigned short length;
	struct capwap_message_element* element;
	struct capwap_returnedmessage_raw_element* dataraw;
	struct capwap_returnedmessage_element* dataelement = (struct capwap_returnedmessage_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_returnedmessage_element));
	
	/* Alloc block of memory */
	length = sizeof(struct capwap_returnedmessage_raw_element) + dataelement->length;
	element = capwap_alloc(sizeof(struct capwap_message_element) + length);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element));
	element->type = htons(CAPWAP_ELEMENT_RETURNEDMESSAGE);
	element->length = htons(length);
	
	dataraw = (struct capwap_returnedmessage_raw_element*)element->data;
	dataraw->reason = dataelement->reason;
	dataraw->length = dataelement->length;
	memcpy(&dataraw->message[0], &dataelement->message[0], dataelement->length);
	
	return element;
}

/* */
int capwap_returnedmessage_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_returnedmessage_element_parsing(struct capwap_message_element* element) {
	unsigned short length;
	struct capwap_returnedmessage_element* data;
	struct capwap_returnedmessage_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_RETURNEDMESSAGE);

	length = ntohs(element->length) - sizeof(struct capwap_returnedmessage_raw_element);
	if (length > CAPWAP_RETURNED_MESSAGE_MAX_LENGTH)  {
		return NULL;
	}
	
	/* */
	dataraw = (struct capwap_returnedmessage_raw_element*)element->data;
	data = (struct capwap_returnedmessage_element*)capwap_alloc(sizeof(struct capwap_returnedmessage_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->reason = dataraw->reason;
	data->length = dataraw->length;
	memcpy(&data->message[0], &dataraw->message[0], dataraw->length);
	
	return data;
}

/* */
void capwap_returnedmessage_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
