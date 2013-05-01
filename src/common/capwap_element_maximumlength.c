#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0              1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Maximum Message Length     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   29 for Maximum Message Length
Length:  2

********************************************************************/

struct capwap_maximumlength_raw_element {
	unsigned short length;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_maximumlength_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_maximumlength_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_maximumlength_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_maximumlength_raw_element));
	element->type = htons(CAPWAP_ELEMENT_MAXIMUMLENGTH);
	element->length = htons(sizeof(struct capwap_maximumlength_raw_element));
	
	((struct capwap_maximumlength_raw_element*)element->data)->length = htons(((struct capwap_maximumlength_element*)data)->length);
	
	return element;
}

/* */
int capwap_maximumlength_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_maximumlength_element_parsing(struct capwap_message_element* element) {
	struct capwap_maximumlength_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_MAXIMUMLENGTH);
	
	if (ntohs(element->length) != sizeof(struct capwap_maximumlength_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_maximumlength_element*)capwap_alloc(sizeof(struct capwap_maximumlength_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->length = ntohs(((struct capwap_maximumlength_raw_element*)element->data)->length);
	return data;
}

/* */
void capwap_maximumlength_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
