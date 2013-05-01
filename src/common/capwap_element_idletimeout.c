#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Timeout                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   23 for Idle Timeout
Length:  4

********************************************************************/

struct capwap_idletimeout_raw_element {
	unsigned long timeout;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_idletimeout_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_idletimeout_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_idletimeout_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_idletimeout_raw_element));
	element->type = htons(CAPWAP_ELEMENT_IDLETIMEOUT);
	element->length = htons(sizeof(struct capwap_idletimeout_raw_element));
	
	((struct capwap_idletimeout_raw_element*)element->data)->timeout = htonl(((struct capwap_idletimeout_element*)data)->timeout);
	
	return element;
}

/* */
int capwap_idletimeout_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_idletimeout_element_parsing(struct capwap_message_element* element) {
	struct capwap_idletimeout_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_IDLETIMEOUT);
	
	if (ntohs(element->length) != sizeof(struct capwap_idletimeout_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_idletimeout_element*)capwap_alloc(sizeof(struct capwap_idletimeout_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->timeout = ntohl(((struct capwap_idletimeout_raw_element*)element->data)->timeout);
	return data;
}

/* */
void capwap_idletimeout_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
