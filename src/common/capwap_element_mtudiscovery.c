#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|  Padding...
+-+-+-+-+-+-+-+-

Type:   52 for MTU Discovery Padding
Length:  variable

********************************************************************/

/* */
struct capwap_message_element* capwap_mtudiscovery_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_mtudiscovery_element* dataelement = (struct capwap_mtudiscovery_element*)data;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(struct capwap_mtudiscovery_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + dataelement->length);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element));
	element->type = htons(CAPWAP_ELEMENT_MTUDISCOVERY);
	element->length = htons(dataelement->length);
	
	if (dataelement->length > 0) {
		memset(element->data, 0xff, dataelement->length);
	}
	
	return element;
}

/* */
int capwap_mtudiscovery_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_mtudiscovery_element_parsing(struct capwap_message_element* element) {
	struct capwap_mtudiscovery_element* data;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_MTUDISCOVERY);
	
	/* */
	data = (struct capwap_mtudiscovery_element*)capwap_alloc(sizeof(struct capwap_mtudiscovery_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	data->length = ntohs(element->length);
	return data;
}

/* */
void capwap_mtudiscovery_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
