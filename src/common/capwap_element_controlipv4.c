#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           WTP Count           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   10 for CAPWAP Control IPv4 Address
Length:   6

********************************************************************/

struct capwap_controlipv4_raw_element {
	unsigned long address;
	unsigned short wtpcount;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_controlipv4_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_controlipv4_element* dataelement = (struct capwap_controlipv4_element*)data;
	struct capwap_controlipv4_raw_element* dataraw;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_controlipv4_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_controlipv4_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_controlipv4_raw_element));
	element->type = htons(CAPWAP_ELEMENT_CONTROLIPV4);
	element->length = htons(sizeof(struct capwap_controlipv4_raw_element));
	
	dataraw = (struct capwap_controlipv4_raw_element*)element->data;
	dataraw->address = dataelement->address.s_addr;
	dataraw->wtpcount = htons(dataelement->wtpcount);

	return element;
}

/* */
int capwap_controlipv4_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_controlipv4_element_parsing(struct capwap_message_element* element) {
	struct capwap_controlipv4_element* data;
	struct capwap_controlipv4_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_CONTROLIPV4);
	
	if (ntohs(element->length) != sizeof(struct capwap_controlipv4_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_controlipv4_element*)capwap_alloc(sizeof(struct capwap_controlipv4_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	dataraw = (struct capwap_controlipv4_raw_element*)element->data;
	data->address.s_addr = dataraw->address;
	data->wtpcount = ntohs(dataraw->wtpcount);
	
	return data;
}

/* */
void capwap_controlipv4_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
