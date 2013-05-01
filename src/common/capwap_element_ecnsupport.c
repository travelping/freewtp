#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|  ECN Support  |
+-+-+-+-+-+-+-+-+

Type:   53 for ECN Support
Length:  1

********************************************************************/

struct capwap_ecnsupport_raw_element {
	char flag;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_ecnsupport_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_ecnsupport_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_ecnsupport_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_ecnsupport_raw_element));
	element->type = htons(CAPWAP_ELEMENT_ECNSUPPORT);
	element->length = htons(sizeof(struct capwap_ecnsupport_raw_element));
	
	((struct capwap_ecnsupport_raw_element*)element->data)->flag = ((struct capwap_ecnsupport_element*)data)->flag;
	
	return element;
}

/* */
int capwap_ecnsupport_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_ecnsupport_element_parsing(struct capwap_message_element* element) {
	struct capwap_ecnsupport_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_ECNSUPPORT);
	
	if (ntohs(element->length) != sizeof(struct capwap_ecnsupport_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_ecnsupport_element*)capwap_alloc(sizeof(struct capwap_ecnsupport_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->flag = ((struct capwap_ecnsupport_raw_element*)element->data)->flag;
	return data;
}

/* */
void capwap_ecnsupport_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
