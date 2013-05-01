#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Result Code                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   33 for Result Code
Length:  4

********************************************************************/

struct capwap_resultcode_raw_element {
	unsigned long code;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_resultcode_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_resultcode_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_resultcode_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_resultcode_raw_element));
	element->type = htons(CAPWAP_ELEMENT_RESULTCODE);
	element->length = htons(sizeof(struct capwap_resultcode_raw_element));
	
	((struct capwap_resultcode_raw_element*)element->data)->code = htonl(((struct capwap_resultcode_element*)data)->code);
	
	return element;
}

/* */
int capwap_resultcode_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_resultcode_element_parsing(struct capwap_message_element* element) {
	struct capwap_resultcode_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_RESULTCODE);
	
	if (ntohs(element->length) != sizeof(struct capwap_resultcode_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_resultcode_element*)capwap_alloc(sizeof(struct capwap_resultcode_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->code = ntohl(((struct capwap_resultcode_raw_element*)element->data)->code);
	return data;
}

/* */
void capwap_resultcode_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
