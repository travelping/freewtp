#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |  Admin State  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   31 for Radio Administrative State
Length:  2

********************************************************************/

struct capwap_radioadmstate_raw_element {
	unsigned char radioid;
	unsigned char state;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_radioadmstate_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_radioadmstate_element* dataelement = (struct capwap_radioadmstate_element*)data;
	struct capwap_radioadmstate_raw_element* dataraw;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_radioadmstate_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_radioadmstate_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_radioadmstate_raw_element));
	element->type = htons(CAPWAP_ELEMENT_RADIOADMSTATE);
	element->length = htons(sizeof(struct capwap_radioadmstate_raw_element));
	
	dataraw = (struct capwap_radioadmstate_raw_element*)element->data;
	dataraw->radioid = dataelement->radioid;
	dataraw->state = dataelement->state;
	
	return element;
}

/* */
int capwap_radioadmstate_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_radioadmstate_element_parsing(struct capwap_message_element* element) {
	struct capwap_radioadmstate_element* data;
	struct capwap_radioadmstate_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_RADIOADMSTATE);
	
	if (ntohs(element->length) != sizeof(struct capwap_radioadmstate_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_radioadmstate_element*)capwap_alloc(sizeof(struct capwap_radioadmstate_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	dataraw = (struct capwap_radioadmstate_raw_element*)element->data;
	data->radioid = dataraw->radioid;
	data->state = dataraw->state;
	
	return data;
}

/* */
void capwap_radioadmstate_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
