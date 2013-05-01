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

Type:   3 for AC IPV6 List
Length:   >= 16

********************************************************************/

struct capwap_acipv6list_raw_element {
	unsigned long address[4];
} __attribute__((__packed__));

/* */
struct capwap_message_element* capwap_acipv6list_element_create(void* data, unsigned long datalength) {
	int i;
	int items;
	unsigned short sizeitems;
	struct capwap_message_element* element;
	capwap_acipv6list_element_array* dataarray = (capwap_acipv6list_element_array*)data;
	struct capwap_acipv6list_raw_element* dataraw;
	
	ASSERT(data != NULL);
	ASSERT(datalength == sizeof(capwap_acipv6list_element_array));
	
	items = min(dataarray->count, CAPWAP_ACIPV6LIST_MAX_ELEMENTS);
	
	/* Alloc block of memory */
	sizeitems = sizeof(struct capwap_acipv6list_raw_element) * items;
	element = capwap_alloc(sizeof(struct capwap_message_element) + sizeitems);
	if (!element) {
		capwap_outofmemory();
	}

	/* Create message element */
	memset(element, 0, sizeof(struct capwap_message_element) + sizeitems);
	element->type = htons(CAPWAP_ELEMENT_ACIPV6LIST);
	element->length = htons(sizeitems);
	
	dataraw = (struct capwap_acipv6list_raw_element*)element->data;
	for (i = 0; i < items; i++) {
		struct capwap_acipv6list_element* dataelement = (struct capwap_acipv6list_element*)capwap_array_get_item_pointer(dataarray, i);
		memcpy(dataraw->address, dataelement->address.s6_addr32, sizeof(unsigned long) * 4);

		/* Next raw item */
		dataraw++;		
	}

	return element;
}

/* */
int capwap_acipv6list_element_validate(struct capwap_message_element* element) {
	/* TODO */
	return 1;
}

/* */
void* capwap_acipv6list_element_parsing(struct capwap_message_element* element) {
	int i;
	int items;
	unsigned short length;
	capwap_acipv6list_element_array* data;
	struct capwap_acipv6list_raw_element* dataraw;
	
	ASSERT(element);
	ASSERT(ntohs(element->type) == CAPWAP_ELEMENT_ACIPV6LIST);
	
	length = ntohs(element->length);
	if ((length > 0) && ((length % sizeof(struct capwap_acipv6list_raw_element)) != 0)) {
		return NULL;
	}

	/* */
	items = length / sizeof(struct capwap_acipv6list_raw_element);
	data = (capwap_acipv6list_element_array*)capwap_array_create(sizeof(struct capwap_acipv6list_element), items);

	/* */
	dataraw = (struct capwap_acipv6list_raw_element*)element->data;
	for (i = 0; i < items; i++) {
		struct capwap_acipv6list_element* dataelement = (struct capwap_acipv6list_element*)capwap_array_get_item_pointer(data, i);
		memcpy(dataelement->address.s6_addr32, dataraw->address, sizeof(unsigned long) * 4);

		/* Next raw item */
		dataraw++;		
	}

	return data;
}

/* */
void capwap_acipv6list_element_free(void* data) {
	ASSERT(data != NULL);
	
	capwap_array_free((capwap_acipv6list_element_array*)data);
}
