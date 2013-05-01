#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Discovery   | Echo Request  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   12 for CAPWAP Timers
Length:  2

********************************************************************/

struct capwap_timers_raw_element {
	unsigned char discovery;
	unsigned char echorequest;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_timers_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_timers_element* dataelement = (struct capwap_timers_element*)data;
	struct capwap_timers_raw_element* dataraw;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_timers_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_timers_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_timers_raw_element));
	element->type = htons(CAPWAP_ELEMENT_TIMERS);
	element->length = htons(sizeof(struct capwap_timers_raw_element));
	
	dataraw = (struct capwap_timers_raw_element*)element->data;
	dataraw->discovery = dataelement->discovery;
	dataraw->echorequest = dataelement->echorequest;
	
	return element;
}

/* */
int capwap_timers_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_timers_element_parsing(struct capwap_message_element* element) {
	struct capwap_timers_element* data;
	struct capwap_timers_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_TIMERS);
	
	if (ntohs(element->length) != sizeof(struct capwap_timers_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_timers_element*)capwap_alloc(sizeof(struct capwap_timers_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	dataraw = (struct capwap_timers_raw_element*)element->data;
	data->discovery = dataraw->discovery;
	data->echorequest = dataraw->echorequest;
	
	return data;
}

/* */
void capwap_timers_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
