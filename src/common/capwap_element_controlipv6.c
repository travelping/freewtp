#include "capwap.h"
#include "capwap_element.h"

/********************************************************************

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           IP Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           WTP Count           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Type:   11 for CAPWAP Control IPv6 Address
Length:   18

********************************************************************/

struct capwap_controlipv6_raw_element {
	unsigned long address[4];
	unsigned short wtpcount;
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_controlipv6_element_create(void* data, unsigned long datalength) {
	struct capwap_message_element* element;
	struct capwap_controlipv6_element* dataelement = (struct capwap_controlipv6_element*)data;
	struct capwap_controlipv6_raw_element* dataraw;
	
	ASSERT(data != NULL);
	ASSERT(datalength >= sizeof(struct capwap_controlipv6_element));
	
	/* Alloc block of memory */
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeof(struct capwap_controlipv6_raw_element));
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeof(struct capwap_controlipv6_raw_element));
	element->type = htons(CAPWAP_ELEMENT_CONTROLIPV6);
	element->length = htons(sizeof(struct capwap_controlipv6_raw_element));
	
	dataraw = (struct capwap_controlipv6_raw_element*)element->data;
	memcpy(dataraw->address, dataelement->address.s6_addr32, sizeof(unsigned long) * 4);
	dataraw->wtpcount = htons(dataelement->wtpcount);

	return element;
}

/* */
int capwap_controlipv6_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_controlipv6_element_parsing(struct capwap_message_element* element) {
	struct capwap_controlipv6_element* data;
	struct capwap_controlipv6_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_CONTROLIPV6);
	
	if (ntohs(element->length) != sizeof(struct capwap_controlipv6_raw_element)) {
		return NULL;
	}

	/* */
	data = (struct capwap_controlipv6_element*)capwap_alloc(sizeof(struct capwap_controlipv6_element));
	if (!data) {
		capwap_outofmemory();
	}

	/* */
	dataraw = (struct capwap_controlipv6_raw_element*)element->data;
	memcpy(data->address.s6_addr32, dataraw->address, sizeof(unsigned long) * 4);
	data->wtpcount = ntohs(dataraw->wtpcount);
	
	return data;
}

/* */
void capwap_controlipv6_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_free(data);
}
