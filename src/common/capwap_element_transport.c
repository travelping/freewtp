#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Transport   |
+-+-+-+-+-+-+-+-+

Type:   51 for CAPWAP Transport Protocol
Length:  1

********************************************************************/

struct capwap_transport_raw_element {
	char type;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_transport_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_transport_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_transport_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_transport_raw_element));
	element->type = htons(CAPWAP_ELEMENT_TRANSPORT);
	element->length = htons(sizeof(struct capwap_transport_raw_element));
	
	((struct capwap_transport_raw_element*)element->data)->type = ((struct capwap_transport_element*)data)->type;
	
	return element;
}

/* */
int capwap_transport_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_transport_element_parsing(struct capwap_message_element* element) {
	struct capwap_transport_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_TRANSPORT);
	
	if (ntohs(element->length) != sizeof(struct capwap_transport_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_transport_element*)capwap_alloc(sizeof(struct capwap_transport_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->type = ((struct capwap_transport_raw_element*)element->data)->type;
	return data;
}

/* */
void capwap_transport_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
