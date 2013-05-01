#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Radio ID    |     State     |     Cause     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   32 for Radio Operational State
Length:  3

********************************************************************/

struct capwap_radiooprstate_raw_element {
	unsigned char radioid;
	unsigned char state;
	unsigned char cause;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_radiooprstate_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_radiooprstate_element* dataelement = (struct capwap_radiooprstate_element*)data;
	struct capwap_radiooprstate_raw_element* dataraw;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_radiooprstate_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_radiooprstate_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_radiooprstate_raw_element));
	element->type = htons(CAPWAP_ELEMENT_RADIOOPRSTATE);
	element->length = htons(sizeof(struct capwap_radiooprstate_raw_element));
	
	dataraw = (struct capwap_radiooprstate_raw_element*)element->data;
	dataraw->radioid = dataelement->radioid;
	dataraw->state = dataelement->state;
	dataraw->cause = dataelement->cause;
	
	return element;
}

/* */
int capwap_radiooprstate_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_radiooprstate_element_parsing(struct capwap_message_element* element) {
	struct capwap_radiooprstate_element* data;
	struct capwap_radiooprstate_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_RADIOOPRSTATE);
	
	if (ntohs(element->length) != sizeof(struct capwap_radiooprstate_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_radiooprstate_element*)capwap_alloc(sizeof(struct capwap_radiooprstate_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	dataraw = (struct capwap_radiooprstate_raw_element*)element->data;
	data->radioid = dataraw->radioid;
	data->state = dataraw->state;
	data->cause = dataraw->cause;
	
	return data;
}

/* */
void capwap_radiooprstate_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
