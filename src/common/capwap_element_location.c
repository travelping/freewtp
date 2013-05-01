#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|   Location ...
+-+-+-+-+-+-+-+-+

Type:   28 for Location Data
Length:   >= 1

********************************************************************/

struct capwap_location_raw_element {
	char value[0];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_location_element_create(void* data, unsigned long datalength) {
	unsigned short namelength;
	struct capwap_message_element* element;
	struct capwap_location_raw_element* dataraw;
	struct capwap_location_element* dataelement = (struct capwap_location_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_location_element));
	
	/* Alloc block of memory */
	namelength = strlen(dataelement->value);
	element = capwap_alloc(sizeof(struct capwap_message_element) + namelength);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + namelength);
	element->type = htons(CAPWAP_ELEMENT_LOCATION);
	element->length = htons(namelength);
	
	dataraw = (struct capwap_location_raw_element*)element->data;
	memcpy(&dataraw->value[0], &dataelement->value[0], namelength);
	return element;
}

/* */
int capwap_location_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_location_element_parsing(struct capwap_message_element* element) {
	unsigned short namelength;
	struct capwap_location_element* data;
	struct capwap_location_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_LOCATION);

	namelength = ntohs(element->length);
	if (!namelength  || (namelength > CAPWAP_LOCATION_MAXLENGTH))  {
		return NULL;
	}

	/* */
	dataraw = (struct capwap_location_raw_element*)element->data;
	data = (struct capwap_location_element*)capwap_alloc(sizeof(struct capwap_location_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	memcpy(&data->value[0], &dataraw->value[0], namelength);
	data->value[namelength] = 0;
	return data;
}

/* */
void capwap_location_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
