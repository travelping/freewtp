#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Statistics Timer       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   36 for Statistics Timer
Length:  2

********************************************************************/

struct capwap_statisticstimer_raw_element {
	unsigned short timer;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_statisticstimer_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_statisticstimer_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_statisticstimer_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_statisticstimer_raw_element));
	element->type = htons(CAPWAP_ELEMENT_STATISTICSTIMER);
	element->length = htons(sizeof(struct capwap_statisticstimer_raw_element));
	
	((struct capwap_statisticstimer_raw_element*)element->data)->timer = htons(((struct capwap_statisticstimer_element*)data)->timer);
	
	return element;
}

/* */
int capwap_statisticstimer_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_statisticstimer_element_parsing(struct capwap_message_element* element) {
	struct capwap_statisticstimer_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_STATISTICSTIMER);
	
	if (ntohs(element->length) != sizeof(struct capwap_statisticstimer_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_statisticstimer_element*)capwap_alloc(sizeof(struct capwap_statisticstimer_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->timer = ntohs(((struct capwap_statisticstimer_raw_element*)element->data)->timer);
	return data;
}

/* */
void capwap_statisticstimer_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
