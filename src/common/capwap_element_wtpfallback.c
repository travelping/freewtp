#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|     Mode      |
+-+-+-+-+-+-+-+-+

Type:   40 for WTP Fallback
Length:  1

********************************************************************/

struct capwap_wtpfallback_raw_element {
	char mode;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_wtpfallback_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_wtpfallback_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_wtpfallback_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_wtpfallback_raw_element));
	element->type = htons(CAPWAP_ELEMENT_WTPFALLBACK);
	element->length = htons(sizeof(struct capwap_wtpfallback_raw_element));
	
	((struct capwap_wtpfallback_raw_element*)element->data)->mode = ((struct capwap_wtpfallback_element*)data)->mode;
	
	return element;
}

/* */
int capwap_wtpfallback_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_wtpfallback_element_parsing(struct capwap_message_element* element) {
	struct capwap_wtpfallback_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_WTPFALLBACK);
	
	if (ntohs(element->length) != sizeof(struct capwap_wtpfallback_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_wtpfallback_element*)capwap_alloc(sizeof(struct capwap_wtpfallback_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->mode = ((struct capwap_wtpfallback_raw_element*)element->data)->mode;
	return data;
}

/* */
void capwap_wtpfallback_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
